import datetime
import email
import uuid
from base64 import b64encode
from hashlib import sha256
from pathlib import Path
from pprint import pprint
from typing import Optional
from Crypto.PublicKey import RSA

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

from mitmproxy import ctx
from mitmproxy.http import HTTPFlow

CERTS_DIR = Path(__file__).parent / "certs"
SBX_QSEALC_CRT = CERTS_DIR / "CB_TPP_SANDBOX_QSEALC_v01.crt"
SBX_QSEALC_KEY = CERTS_DIR / "CB_TPP_SANDBOX_QSEALC_v01.key"
SBX_QWAC_CRT = CERTS_DIR / "CB_TPP_SANDBOX_QWAC_v01.crt"
SBX_QWAC_KEY = CERTS_DIR / "CB_TPP_SANDBOX_QWAC_v01.key"


def compute_signing_string(method: str, request_id: str, date: str, path: str, digest: Optional[str] = None) -> bytes:
    print(f"Computing signing string for {method} {path} {date} {request_id}")
    signing_string = f"(request-target): {method.lower()} {path}\n"
    if digest is not None:
        signing_string += f"digest: {digest}\n"
    signing_string += f"tpp-request-id: {request_id}\ndate: {date}"
    return signing_string.encode()


def compute_signature_hash(sign_string: bytes) -> bytes:
    with SBX_QWAC_KEY.open("r") as private_key:
        key_pair = RSA.importKey(private_key.read())
    hashed_string = int.from_bytes(sha256(sign_string).digest(), byteorder='big')
    signature = pow(hashed_string, key_pair.d, key_pair.n)
    return b64encode(hex(signature).encode())


def compute_signature_hash_v2(sign_string: bytes) -> bytes:
    with SBX_QSEALC_KEY.open("rb") as private_key_file:
        private_key = serialization.load_pem_private_key(
            private_key_file.read(),
            password=None
        )
    signature_value = private_key.sign(
        sign_string,
        padding.PKCS1v15(
        ),
        hashes.SHA256()
    )
    return b64encode(signature_value)


def compute_date_header() -> str:
    #  Tue, 12 Mar 2019 08:49:49 GMT
    return email.utils.formatdate(int(datetime.datetime.now().timestamp()), usegmt=True)


def compute_tpp_request_id() -> str:
    return str(uuid.uuid4())


def compute_digest(body: Optional[bytes]) -> Optional[bytes]:
    if body is None or body == b"":
        return None
    body_hashed = sha256(body).digest()

    return f"SHA-256={b64encode(body_hashed).decode()}".encode("utf-8")


def compute_signature_header(key_id: str, signing_string: bytes, digest: Optional[bytes] = None) -> bytes:
    signature = compute_signature_hash_v2(signing_string)
    return f'keyId="{key_id}",algorithm="rsa-sha256",headers="(request-target) ' \
           f'{" digest" if digest is not None else ""}' \
           f'tpp-request-id date",signature="{signature.decode()}"'.encode()


class Dummy:
    def __init__(self) -> None:
        pass

    def request(self, flow: HTTPFlow):
        ctx.log.info(f"Got request {flow.request.host}")
        ctx.log.info(flow.request.content)
        digest = compute_digest(flow.request.content)
        date_value = compute_date_header()
        request_id = compute_tpp_request_id()
        signing_string = compute_signing_string(method=flow.request.method, request_id=request_id, date=date_value,
                                                path=flow.request.path, digest=digest)
        signature_value = compute_signature_hash(signing_string)
        signature_header = compute_signature_header(key_id="TEST_TPP_APP_01", signing_string=signing_string,
                                                    digest=digest)
        if digest is not None:
            flow.request.headers["Digest"] = digest
        flow.request.headers['Signature'] = signature_header
        flow.request.headers['Date'] = date_value
        flow.request.headers['TPP-Request-ID'] = request_id
        pprint(flow.request.headers)


addons = [Dummy()]

if __name__ == '__main__':
    print(compute_signature_hash(compute_signing_string("post", path="/private/test01", date=compute_date_header(),
                                                        request_id=compute_tpp_request_id())))

from http_proxy import __version__
from http_proxy.dummy_addon import compute_date_header, compute_signature


def test_version():
    assert __version__ == '0.1.0'


def test_get_date_header():
    date_str = compute_date_header()
    print(date_str)
    assert True


def test_compute_signature():
    headers = compute_signature()
    print(headers)
    assert True

import pytest
from src.utils.safe_http import validate_url, UnsafeURL
from src.utils.validators import validate_domain, defang


@pytest.mark.parametrize("url", [
    "http://127.0.0.1",
    "http://192.168.1.1",
    "http://169.254.169.254/latest/meta-data",
    "http://localhost:8080",
    "file:///etc/passwd",
    "ftp://example.com",
])
def test_blocks_unsafe_urls(url):
    with pytest.raises(UnsafeURL):
        validate_url(url)


@pytest.mark.parametrize("d", ["", "not a domain", "a..com", "evil.com/path", "x" * 300 + ".com"])
def test_rejects_bad_domains(d):
    with pytest.raises(ValueError):
        validate_domain(d)


def test_accepts_good_domain():
    assert validate_domain(" Google.com ") == "google.com"


def test_defang():
    assert defang("http://evil.com") == "hxxp://evil[.]com"

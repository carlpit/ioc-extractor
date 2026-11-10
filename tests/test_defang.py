import pytest

from ioc_extractor import defang, refang


@pytest.mark.parametrize(
    ("defanged", "expected"),
    [
        ("hxxp://evil[.]com", "http://evil.com"),
        ("hXXps://evil(.)com", "https://evil.com"),
        ("evil[dot]com", "evil.com"),
        ("evil{.}com", "evil.com"),
        ("https[://]evil[.]com", "https://evil.com"),
        ("user[@]mail[.]ru", "user@mail.ru"),
        ("user(at)mail(.)ru", "user@mail.ru"),
        ("1.2.3[.]4", "1.2.3.4"),
        ("fxp://files[.]evil[.]net", "ftp://files.evil.net"),
    ],
)
def test_refang(defanged, expected):
    assert refang(defanged) == expected


@pytest.mark.parametrize(
    ("value", "ioc_type", "expected"),
    [
        ("evil.com", "domain", "evil[.]com"),
        ("8.8.8.8", "ipv4", "8[.]8[.]8[.]8"),
        ("a@b.com", "email", "a[@]b[.]com"),
        ("https://evil.com/x.php?a=1", "url", "hxxps[://]evil[.]com/x.php?a=1"),
        ("ftp://evil.com/f", "url", "fxp[://]evil[.]com/f"),
        ("CVE-2021-44228", "cve", "CVE-2021-44228"),
    ],
)
def test_defang(value, ioc_type, expected):
    assert defang(value, ioc_type) == expected


@pytest.mark.parametrize(
    ("value", "ioc_type"),
    [
        ("evil.com", "domain"),
        ("a@b.co", "email"),
        ("https://x.y.org/p", "url"),
        ("1.2.3.4", "ipv4"),
    ],
)
def test_roundtrip(value, ioc_type):
    assert refang(defang(value, ioc_type)) == value

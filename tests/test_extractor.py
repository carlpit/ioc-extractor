from pathlib import Path

import pytest

from ioc_extractor import extract

SAMPLE = (Path(__file__).parent.parent / "examples" / "sample_report.txt").read_text()


@pytest.fixture(scope="module")
def sample():
    return extract(SAMPLE).to_dict()


def test_urls_are_refanged_and_cleaned(sample):
    assert "https://cdn-docs.example-cdn.net/view?id=8841" in sample["url"]
    assert "https://www.google.com/search?q=test" in sample["url"]


def test_domains(sample):
    domains = set(sample["domain"])
    assert {"update-check.badsite.org", "cdn-docs.example-cdn.net", "docs.microsoft.com"} <= domains


def test_file_names_are_not_domains(sample):
    for fname in ("config.json", "loader.dll", "readme.txt", "invoice.pdf.exe"):
        assert fname not in sample["domain"]


def test_email_domain_is_not_duplicated_as_domain(sample):
    assert sample["email"] == ["billing@invoice-update.example"]
    assert "invoice-update.example" not in sample["domain"]


def test_ipv4(sample):
    assert sample["ipv4"] == ["10.20.30.40", "198.51.100.77", "203.0.113.45"]


def test_version_number_is_not_ip(sample):
    assert "1.2.3.4" not in sample["ipv4"]
    assert "2.3.4.5" not in sample["ipv4"]


def test_ipv6(sample):
    assert sample["ipv6"] == ["2001:db8:85a3::8a2e:370:7334"]


def test_hashes(sample):
    assert sample["md5"] == ["44d88612fea8a8f36de82e1278abb02f"]
    assert sample["sha1"] == ["3395856ce81f2b7382dee72602f798b642f14140"]
    assert sample["sha256"] == ["275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"]


def test_cve_normalized_to_upper(sample):
    assert sample["cve"] == ["CVE-2023-4966", "CVE-2024-3400"]


def test_mitre_attack(sample):
    assert sample["mitre_attack"] == ["T1053.005", "T1059.001"]


def test_exclude_private():
    result = extract("hosts 10.0.0.5 192.168.1.1 127.0.0.1 8.8.8.8", exclude_private=True)
    assert result.to_dict()["ipv4"] == ["8.8.8.8"]


def test_allowlist_matches_subdomains():
    result = extract("mail.google.com evil.com google.com", allowlist=["google.com"])
    assert result.to_dict()["domain"] == ["evil.com"]


def test_allowlist_applies_to_url_and_email_hosts():
    text = "https://www.google.com/q bob@google.com https://evil.com/x"
    result = extract(text, allowlist=["google.com"]).to_dict()
    assert result["url"] == ["https://evil.com/x"]
    assert "email" not in result


def test_documentation_ranges_are_not_public():
    # 203.0.113.0/24 (TEST-NET-3) and 2001:db8::/32 are reserved for docs.
    result = extract("203.0.113.5 2001:db8::1 1.1.1.1", exclude_private=True).to_dict()
    assert result == {"ipv4": ["1.1.1.1"]}


def test_type_filter():
    result = extract("evil.com 1.1.1.1 CVE-2021-44228", types=["cve"])
    assert result.to_dict() == {"cve": ["CVE-2021-44228"]}


def test_unknown_type_raises():
    with pytest.raises(ValueError):
        extract("x", types=["nope"])


def test_invalid_ip_octets_rejected():
    assert "ipv4" not in extract("999.1.1.1 and 256.256.256.256").to_dict()


def test_url_trailing_punctuation_stripped():
    text = "See (http://evil.com/a). Also http://bad.org/x, ok."
    assert extract(text).to_dict()["url"] == ["http://bad.org/x", "http://evil.com/a"]


def test_mac_and_time_not_ipv6():
    assert "ipv6" not in extract("mac 00:1a:2b:3c:4d:5e at 10:30:45").to_dict()


def test_deduplication():
    result = extract("evil.com EVIL.com evil.com")
    assert result.to_dict()["domain"] == ["evil.com"]
    assert len(result) == 1

def test_url_keeps_balanced_parentheses_and_brackets():
    text = "See http://evil.com/func(1) and http://evil.com/arr[0] please."
    assert extract(text).to_dict()["url"] == [
        "http://evil.com/arr[0]",
        "http://evil.com/func(1)",
    ]


def test_url_strips_unmatched_closers_from_prose():
    text = "See (http://evil.com/a) and [http://evil.com/b]."
    assert extract(text).to_dict()["url"] == ["http://evil.com/a", "http://evil.com/b"]


def test_cve_accepts_ids_longer_than_seven_digits():
    assert extract("see CVE-2026-12345678").to_dict()["cve"] == ["CVE-2026-12345678"]


def test_mitre_attack_includes_ics_techniques():
    result = extract("ICS T0801 and enterprise T1059.001").to_dict()
    assert result["mitre_attack"] == ["T0801", "T1059.001"]


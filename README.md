# ioc-extractor

[![CI](https://github.com/carlpit/ioc-extractor/actions/workflows/ci.yml/badge.svg)](https://github.com/carlpit/ioc-extractor/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)

Extract **Indicators of Compromise (IOCs)** from threat-intelligence reports, e-mails and logs —
with refanging, false-positive filtering, allowlists and analyst-friendly output.

Pure Python standard library. No dependencies, no network calls.

## Why

Threat reports publish indicators *defanged* (`hxxps://evil[.]com`) and mixed with prose,
file names and version numbers. Copying them by hand into a SIEM, blocklist or MISP event is slow
and error-prone. `ioc-extractor` turns a report into a clean, deduplicated list in one command.

## Features

| Type | Example | Notes |
|---|---|---|
| `url` | `https://cdn.example.net/view?id=1` | trailing punctuation and stray `)` removed |
| `domain` | `update-check.badsite.org` | file names like `loader.dll`, `config.json` filtered out |
| `ipv4` / `ipv6` | `203.0.113.45`, `2001:db8::1` | validated with `ipaddress`; version strings like `1.2.3.4.5` ignored |
| `email` | `billing@invoice-update.example` | its domain is not duplicated as a `domain` |
| `md5` / `sha1` / `sha256` | `44d886…` | normalised to lowercase |
| `cve` | `CVE-2024-3400` | normalised to uppercase |
| `mitre_attack` | `T1059.001` | ATT&CK technique and sub-technique IDs |

- **Refang** input: `hxxp`, `[.]`, `(.)`, `{.}`, `[dot]`, `[@]`, `(at)`, `[://]`, `fxp`
- **Defang** output for safe sharing (Markdown reports are defanged by default)
- `--exclude-private`: drops private, loopback, link-local and documentation ranges
- `--allowlist`: ignore known-good values; a parent domain covers subdomains, URLs and e-mails
- Output as **JSON**, **CSV** or **Markdown**; reads files or `stdin`

## Install

```bash
git clone https://github.com/carlpit/ioc-extractor.git
cd ioc-extractor
pip install -e ".[dev]"
```

## Usage

```bash
# JSON to stdout
ioc-extractor examples/sample_report.txt

# CSV, defanged, only network indicators
ioc-extractor report.txt -f csv --defang -t url,domain,ipv4

# Markdown report for a ticket, ignoring known-good domains
ioc-extractor report.txt -f md --allowlist examples/allowlist.txt -o iocs.md

# Pipe from anything
curl -s https://example.org/advisory.txt | ioc-extractor -f csv
```

Example (excerpt) for [`examples/sample_report.txt`](examples/sample_report.txt):

```json
{
  "total": 18,
  "iocs": {
    "url": ["https://cdn-docs.example-cdn.net/view?id=8841", "..."],
    "domain": ["cdn-docs.example-cdn.net", "docs.microsoft.com", "update-check.badsite.org", "..."],
    "ipv4": ["10.20.30.40", "198.51.100.77", "203.0.113.45"],
    "cve": ["CVE-2023-4966", "CVE-2024-3400"],
    "mitre_attack": ["T1053.005", "T1059.001"]
  }
}
```

### As a library

```python
from ioc_extractor import extract, defang

result = extract(open("report.txt").read(), exclude_private=True, allowlist=["microsoft.com"])
for ioc_type, value in result.rows():
    print(ioc_type, defang(value, ioc_type))
```

## Design notes

- **Precision over recall.** A blocklist with false positives breaks production (blocking
  `config.json` as a domain is a classic). Domain candidates whose TLD is a common file
  extension are dropped; IPs must be valid addresses; e-mail domains are not double-counted.
- **Order of extraction** is irrelevant to the result because each type is matched independently
  and stored in sets, so results are deterministic and sorted.
- The sample report is **fictional** and uses documentation IP ranges (RFC 5737 / RFC 3849).

## Tests

```bash
pytest            # unit, CLI and doctests
ruff check .
```

## Roadmap

- [ ] STIX 2.1 bundle export
- [ ] MISP event JSON export
- [ ] PDF / HTML input
- [ ] Optional enrichment (VirusTotal, AbuseIPDB) behind API keys

## License

MIT

---

**Desenvolvido por [carlpit](https://github.com/carlpit)** · Developed by carlpit

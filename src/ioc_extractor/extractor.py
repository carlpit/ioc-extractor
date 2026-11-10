"""Core extraction logic: find Indicators of Compromise (IOCs) in free text."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from .defang import refang

IOC_TYPES: tuple[str, ...] = (
    "url",
    "domain",
    "ipv4",
    "ipv6",
    "email",
    "md5",
    "sha1",
    "sha256",
    "cve",
    "mitre_attack",
)

# File extensions that look like TLDs and generate false positives
# ("payload.exe", "config.json"). Some (.zip, .sh) are real TLDs, but in
# reports they are almost always file names.
FILE_EXTENSIONS: frozenset[str] = frozenset(
    {
        "exe", "dll", "sys", "bat", "cmd", "ps1", "vbs", "js", "jar", "py",
        "sh", "bin", "elf", "so", "msi", "lnk", "scr", "hta",
        "txt", "log", "csv", "json", "xml", "yaml", "yml", "ini", "cfg", "conf",
        "doc", "docx", "xls", "xlsx", "xlsm", "ppt", "pptx", "pdf", "rtf",
        "zip", "rar", "7z", "gz", "tar", "iso", "img",
        "png", "jpg", "jpeg", "gif", "bmp", "svg", "html", "htm", "php", "asp",
        "aspx", "md", "tmp", "dat", "db",
    }
)

_RE = {
    "url": re.compile(r"\b(?:https?|ftp)://[^\s<>\"'`]+", re.IGNORECASE),
    "email": re.compile(
        r"\b[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}\b"
    ),
    "domain": re.compile(
        r"(?<![@\w.-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}\b(?![\w-])"
    ),
    "ipv4": re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.]*\d)"),
    "ipv6": re.compile(r"(?<![\w:])(?:[A-Fa-f0-9]{0,4}:){2,7}[A-Fa-f0-9]{0,4}(?![\w:])"),
    "sha256": re.compile(r"\b[A-Fa-f0-9]{64}\b"),
    "sha1": re.compile(r"\b[A-Fa-f0-9]{40}\b"),
    "md5": re.compile(r"\b[A-Fa-f0-9]{32}\b"),
    "cve": re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE),
    "mitre_attack": re.compile(r"\bT\d{4}(?:\.\d{3})?\b"),
}

# Strip sentence punctuation, but keep ')' and ']' so paths like /func(1)
# or /arr[0] are not truncated. Unmatched closers from prose are handled in
# _clean_url.
_TRAILING_PUNCT = ".,;:!?'\""


@dataclass
class ExtractionResult:
    """Deduplicated indicators grouped by type."""

    iocs: dict[str, set[str]] = field(default_factory=lambda: {t: set() for t in IOC_TYPES})

    def add(self, ioc_type: str, value: str) -> None:
        self.iocs[ioc_type].add(value)

    def merge(self, other: ExtractionResult) -> None:
        for ioc_type, values in other.iocs.items():
            self.iocs[ioc_type].update(values)

    def to_dict(self, include_empty: bool = False) -> dict[str, list[str]]:
        return {
            t: sorted(v) for t, v in self.iocs.items() if v or include_empty
        }

    def rows(self) -> list[tuple[str, str]]:
        """Flat ``(type, value)`` list, stable order."""
        return [(t, v) for t in IOC_TYPES for v in sorted(self.iocs[t])]

    def __len__(self) -> int:
        return sum(len(v) for v in self.iocs.values())


def _clean_url(url: str) -> str:
    url = url.rstrip(_TRAILING_PUNCT)
    # Remove unmatched closers left from prose such as "(see http://x.com)"
    # or "[see http://x.com]".
    changed = True
    while changed:
        changed = False
        if url.endswith(")") and url.count("(") < url.count(")"):
            url = url[:-1].rstrip(_TRAILING_PUNCT)
            changed = True
        if url.endswith("]") and url.count("[") < url.count("]"):
            url = url[:-1].rstrip(_TRAILING_PUNCT)
            changed = True
    return url


def _valid_ipv4(candidate: str) -> ipaddress.IPv4Address | None:
    try:
        return ipaddress.IPv4Address(candidate)
    except ValueError:
        return None


def _valid_ipv6(candidate: str) -> ipaddress.IPv6Address | None:
    if candidate.count(":") < 2 or not re.search(r"[A-Fa-f0-9]", candidate):
        return None
    try:
        return ipaddress.IPv6Address(candidate)
    except ValueError:
        return None


def _is_public(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return ip.is_global and not ip.is_multicast


def _host_of(ioc_type: str, value: str) -> str | None:
    if ioc_type == "url":
        return (urlsplit(value).hostname or "").lower() or None
    if ioc_type == "email":
        return value.rsplit("@", 1)[-1].lower()
    return None


def _allowlisted(value: str, allowlist: set[str], ioc_type: str = "") -> bool:
    if not allowlist:
        return False
    value = value.lower()
    if value in allowlist:
        return True
    host = _host_of(ioc_type, value)
    if host is not None:
        value = host
        if value in allowlist:
            return True
    # Domain suffix match: "google.com" allowlists "mail.google.com".
    return any(value.endswith("." + entry) for entry in allowlist)


def extract(
    text: str,
    *,
    types: Iterable[str] | None = None,
    exclude_private: bool = False,
    allowlist: Iterable[str] | None = None,
    do_refang: bool = True,
) -> ExtractionResult:
    """Extract IOCs from *text*.

    Args:
        text: Free text (report, e-mail, log, HTML stripped of tags...).
        types: Restrict to these IOC types (default: all).
        exclude_private: Drop private/reserved/loopback IP addresses.
        allowlist: Values or parent domains to ignore (case-insensitive).
        do_refang: Refang ``hxxp``/``[.]`` notation before extracting.
    """
    wanted = set(types) if types else set(IOC_TYPES)
    unknown = wanted - set(IOC_TYPES)
    if unknown:
        raise ValueError(f"Unknown IOC type(s): {', '.join(sorted(unknown))}")

    allow = {a.strip().lower() for a in (allowlist or []) if a.strip()}
    if do_refang:
        text = refang(text)

    result = ExtractionResult()

    def keep(ioc_type: str, value: str) -> None:
        if ioc_type in wanted and not _allowlisted(value, allow, ioc_type):
            result.add(ioc_type, value)

    for match in _RE["url"].finditer(text):
        url = _clean_url(match.group())
        if "://" in url and len(url.split("://", 1)[1]) > 0:
            keep("url", url)

    for match in _RE["email"].finditer(text):
        keep("email", match.group().lower())

    for match in _RE["domain"].finditer(text):
        domain = match.group().lower().rstrip(".")
        tld = domain.rsplit(".", 1)[-1]
        if tld not in FILE_EXTENSIONS:
            keep("domain", domain)

    for match in _RE["ipv4"].finditer(text):
        ip4 = _valid_ipv4(match.group())
        if ip4 and (not exclude_private or _is_public(ip4)):
            keep("ipv4", str(ip4))

    for match in _RE["ipv6"].finditer(text):
        ip6 = _valid_ipv6(match.group())
        if ip6 and (not exclude_private or _is_public(ip6)):
            keep("ipv6", ip6.compressed)

    for ioc_type in ("sha256", "sha1", "md5"):
        for match in _RE[ioc_type].finditer(text):
            keep(ioc_type, match.group().lower())

    for match in _RE["cve"].finditer(text):
        keep("cve", match.group().upper())

    for match in _RE["mitre_attack"].finditer(text):
        keep("mitre_attack", match.group())

    return result

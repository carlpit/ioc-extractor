"""Refang and defang helpers.

Threat-intel reports usually "defang" indicators so they cannot be clicked
by accident (``hxxp://evil[.]com``). Before extracting we *refang* the text
back to its real form; on output we can *defang* again for safe sharing.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

# Order matters: longer / more specific patterns first.
_REFANG_RULES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\bh(?:xx|XX|Xx|xX)p(s?)\b"), r"http\1"),
    (re.compile(r"\bf(?:x|X)p\b"), "ftp"),
    (re.compile(r"\[\s*:\s*/\s*/\s*\]"), "://"),
    (re.compile(r"\[\s*:\s*\]"), ":"),
    (re.compile(r"[\[\(\{]\s*(?:\.|dot|DOT)\s*[\]\)\}]"), "."),
    (re.compile(r"[\[\(\{]\s*(?:@|at|AT)\s*[\]\)\}]"), "@"),
    (re.compile(r"\\\."), "."),
]


def refang(text: str) -> str:
    """Convert defanged indicators in *text* back to their original form.

    >>> refang("hxxps://evil[.]com/a and user[@]mail(.)ru")
    'https://evil.com/a and user@mail.ru'
    """
    for pattern, replacement in _REFANG_RULES:
        text = pattern.sub(replacement, text)
    return text


def _defang_host(host: str) -> str:
    return host.replace(".", "[.]")


def defang(value: str, ioc_type: str) -> str:
    """Defang a single indicator according to its type.

    Hashes, CVEs and ATT&CK IDs are harmless and returned unchanged.
    """
    if ioc_type in {"ipv4", "ipv6", "domain"}:
        return _defang_host(value)
    if ioc_type == "email":
        local, _, domain = value.partition("@")
        return f"{local}[@]{_defang_host(domain)}"
    if ioc_type == "url":
        parts = urlsplit(value)
        scheme = re.sub(r"^http", "hxxp", parts.scheme)
        scheme = re.sub(r"^ftp", "fxp", scheme)
        rest = value[len(parts.scheme) + 3 + len(parts.netloc):]
        return f"{scheme}[://]{_defang_host(parts.netloc)}{rest}"
    return value

"""Output formats: JSON, CSV and Markdown."""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone

from .defang import defang
from .extractor import ExtractionResult


def _value(ioc_type: str, value: str, defanged: bool) -> str:
    return defang(value, ioc_type) if defanged else value


def to_json(result: ExtractionResult, *, defanged: bool = False, source: str | None = None) -> str:
    data = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source": source,
        "total": len(result),
        "defanged": defanged,
        "iocs": {
            t: [_value(t, v, defanged) for v in values]
            for t, values in result.to_dict().items()
        },
    }
    return json.dumps(data, indent=2, ensure_ascii=False)


def to_csv(result: ExtractionResult, *, defanged: bool = False) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(["type", "value"])
    for ioc_type, value in result.rows():
        writer.writerow([ioc_type, _value(ioc_type, value, defanged)])
    return buffer.getvalue()


def to_markdown(result: ExtractionResult, *, defanged: bool = True) -> str:
    """Markdown report. Defanged by default because it is meant to be shared."""
    lines = ["# IOC report", "", f"Total indicators: **{len(result)}**", ""]
    for ioc_type, values in result.to_dict().items():
        lines += [f"## {ioc_type} ({len(values)})", "", "| value |", "|---|"]
        lines += [f"| `{_value(ioc_type, v, defanged)}` |" for v in values]
        lines.append("")
    return "\n".join(lines)


FORMATTERS = {"json": to_json, "csv": to_csv, "md": to_markdown}

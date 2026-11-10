"""Command-line interface: ``ioc-extractor report.txt -f csv``."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .exporters import to_csv, to_json, to_markdown
from .extractor import IOC_TYPES, ExtractionResult, extract


def _read_allowlist(path: Path) -> list[str]:
    lines = path.read_text(encoding="utf-8").splitlines()
    return [ln.split("#", 1)[0].strip() for ln in lines if ln.split("#", 1)[0].strip()]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ioc-extractor",
        description="Extract Indicators of Compromise (URLs, domains, IPs, hashes, "
        "e-mails, CVEs, MITRE ATT&CK IDs) from threat-intel reports and logs.",
    )
    p.add_argument("files", nargs="*", type=Path, help="input files (default: stdin)")
    p.add_argument("-f", "--format", choices=["json", "csv", "md"], default="json")
    p.add_argument("-o", "--output", type=Path, help="write to file instead of stdout")
    p.add_argument(
        "-t", "--types",
        help=f"comma-separated subset of: {','.join(IOC_TYPES)}",
    )
    p.add_argument("--defang", action="store_true", help="defang indicators in the output")
    p.add_argument("--no-defang", action="store_true", help="markdown only: keep raw values")
    p.add_argument("--exclude-private", action="store_true",
                   help="drop private, loopback and reserved IPs")
    p.add_argument("--allowlist", type=Path, help="file with values/domains to ignore")
    p.add_argument("--no-refang", action="store_true", help="do not refang input first")
    p.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    types = [t.strip() for t in args.types.split(",")] if args.types else None
    allowlist = _read_allowlist(args.allowlist) if args.allowlist else None

    sources: list[tuple[str, str]] = []
    if args.files:
        for path in args.files:
            try:
                sources.append((str(path), path.read_text(encoding="utf-8", errors="replace")))
            except OSError as exc:
                print(f"error: cannot read {path}: {exc}", file=sys.stderr)
                return 2
    else:
        sources.append(("stdin", sys.stdin.read()))

    result = ExtractionResult()
    try:
        for _, text in sources:
            result.merge(
                extract(
                    text,
                    types=types,
                    exclude_private=args.exclude_private,
                    allowlist=allowlist,
                    do_refang=not args.no_refang,
                )
            )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    source_label = ", ".join(name for name, _ in sources)
    if args.format == "json":
        out = to_json(result, defanged=args.defang, source=source_label)
    elif args.format == "csv":
        out = to_csv(result, defanged=args.defang)
    else:
        out = to_markdown(result, defanged=not args.no_defang)

    if args.output:
        args.output.write_text(out + ("" if out.endswith("\n") else "\n"), encoding="utf-8")
        print(f"{len(result)} indicators written to {args.output}", file=sys.stderr)
    else:
        print(out)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

import csv
import io
import json
from pathlib import Path

from ioc_extractor.cli import main

EXAMPLES = Path(__file__).parent.parent / "examples"
REPORT = str(EXAMPLES / "sample_report.txt")


def test_json_output(capsys):
    assert main([REPORT]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["total"] > 10
    assert "203.0.113.45" in data["iocs"]["ipv4"]


def test_csv_defanged(capsys):
    assert main([REPORT, "-f", "csv", "--defang", "-t", "ipv4"]) == 0
    rows = list(csv.reader(io.StringIO(capsys.readouterr().out)))
    assert rows[0] == ["type", "value"]
    assert ["ipv4", "203[.]0[.]113[.]45"] in rows


def test_markdown_is_defanged_by_default(capsys):
    assert main([REPORT, "-f", "md", "-t", "domain"]) == 0
    out = capsys.readouterr().out
    assert "update-check[.]badsite[.]org" in out


def test_allowlist_and_output_file(tmp_path):
    out = tmp_path / "iocs.json"
    assert main([REPORT, "--allowlist", str(EXAMPLES / "allowlist.txt"), "-o", str(out)]) == 0
    data = json.loads(out.read_text())
    assert "docs.microsoft.com" not in data["iocs"]["domain"]


def test_stdin(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO("beacon to hxxp://bad[.]org"))
    assert main(["-f", "csv"]) == 0
    assert "url,http://bad.org" in capsys.readouterr().out


def test_bad_type_returns_error(capsys):
    assert main([REPORT, "-t", "foo"]) == 2
    assert "Unknown IOC type" in capsys.readouterr().err


def test_missing_file(capsys):
    assert main(["/no/such/file.txt"]) == 2

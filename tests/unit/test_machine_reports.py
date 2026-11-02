import json
from xml.etree import ElementTree as ET

from typer.testing import CliRunner

from vesk.cli import app
from vesk.report.model import Results
from vesk.report.render import NOTICE, render

R = Results.model_validate(
    {
        "schema_version": 2,
        "target": "http://x/v1",
        "probes": [
            {
                "id": "pii_leakage",
                "name": "PII Leakage",
                "status": "fail",
                "cases": [
                    {"id": "a", "status": "fail"},
                    {"id": "b", "status": "pass"},
                    {"id": "c", "status": "inconclusive"},
                    {"id": "d", "status": "error"},
                ],
            }
        ],
    }
)


def test_sarif():
    d = json.loads(render(R, "sarif"))
    assert d["version"] == "2.1.0"
    res = d["runs"][0]["results"]
    assert [x["level"] for x in res] == ["error", "warning", "error"]
    assert d["runs"][0]["properties"]["notice"] == NOTICE


def test_junit():
    root = ET.fromstring(render(R, "junit"))
    s = root.find("testsuite")
    assert (s.get("tests"), s.get("failures"), s.get("errors"), s.get("skipped")) == (
        "4",
        "1",
        "1",
        "1",
    )


def test_sidecar(tmp_path):
    src = tmp_path / "r.json"
    src.write_text(R.model_dump_json())
    out = tmp_path / "r.sarif"
    res = CliRunner().invoke(app, ["report", str(src), "--format", "sarif", "-o", str(out)])
    assert res.exit_code == 0
    assert (tmp_path / "r.sarif.sha256").read_text().endswith("  r.sarif\n")

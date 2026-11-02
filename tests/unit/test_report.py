import json

import pytest
from typer.testing import CliRunner

from vesk.cli import app
from vesk.report.model import Results
from vesk.report.render import DISCLAIMER, ReportError, render

runner = CliRunner()

RESULTS = {
    "target": "http://localhost:8000/v1",
    "model": "m",
    "probes": [
        {"id": "inj", "name": "Injection", "category": "prompt-injection", "status": "pass",
         "cases": [{"id": "a", "passed": True}]},
        {"id": "pii", "name": "PII", "category": "pii", "status": "fail",
         "cases": [{"id": "b", "passed": False, "prompt": "<script>x</script>",
                    "response": "a`b\nc", "evidence": "leaked"}]},
        {"id": "jb", "status": "error", "error": "timeout"},
    ],
}


@pytest.fixture
def results_file(tmp_path):
    p = tmp_path / "results.json"
    p.write_text(json.dumps(RESULTS))
    return p


@pytest.mark.parametrize("fmt", ["md", "html"])
def test_disclaimer_present(fmt):
    out = render(Results.model_validate(RESULTS), fmt)
    assert "not legal or compliance advice" in out
    assert DISCLAIMER.split(",")[0] in out


def test_markdown_summary_and_details():
    out = render(Results.model_validate(RESULTS), "md")
    assert "1 passed, 1 failed, 1 errored (3 probes)" in out
    assert "Error: timeout" in out
    assert "Evidence: leaked" in out
    assert "a'b c" in out


def test_html_escapes():
    out = render(Results.model_validate(RESULTS), "html")
    assert "<script>x" not in out
    assert "&lt;script&gt;" in out


def test_empty_results():
    out = render(Results(), "md")
    assert "0 passed" in out and "not legal or compliance advice" in out


def test_unknown_format():
    with pytest.raises(ReportError):
        render(Results(), "pdf")


def test_cli_stdout(results_file):
    r = runner.invoke(app, ["report", str(results_file)])
    assert r.exit_code == 0
    assert "not legal or compliance advice" in r.output


def test_cli_output_file(results_file, tmp_path):
    out = tmp_path / "r.html"
    r = runner.invoke(app, ["report", str(results_file), "--format", "html", "-o", str(out)])
    assert r.exit_code == 0
    assert "<html" in out.read_text()


def test_cli_missing_file(tmp_path):
    r = runner.invoke(app, ["report", str(tmp_path / "nope.json")])
    assert r.exit_code == 1


def test_cli_bad_json(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("{")
    assert runner.invoke(app, ["report", str(p)]).exit_code == 1


def test_cli_bad_schema(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text(json.dumps({"probes": [{"id": "x", "status": "weird"}]}))
    assert runner.invoke(app, ["report", str(p)]).exit_code == 1


def test_cli_bad_format(results_file):
    assert runner.invoke(app, ["report", str(results_file), "--format", "pdf"]).exit_code == 1

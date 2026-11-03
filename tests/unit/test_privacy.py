import json
import os
import time

import pytest
from typer.testing import CliRunner

from vesk import privacy
from vesk.cli import app
from vesk.report.model import Results
from vesk.report.render import render

runner = CliRunner()

SECRET = "TOPSECRET-RESPONSE"
RESULTS = {
    "schema_version": 2,
    "target": "http://x/v1",
    "model": "m",
    "metadata": {"system_prompt": {"included": True, "text": "SYSPROMPT-TEXT"}},
    "probes": [
        {
            "id": "p",
            "status": "fail",
            "cases": [
                {
                    "id": "c",
                    "status": "fail",
                    "trials": [
                        {
                            "status": "fail",
                            "request_messages": [
                                {"role": "system", "content": "SYSPROMPT-TEXT"},
                                {"role": "user", "content": "PROMPT-SECRET"},
                            ],
                            "response": SECRET,
                            "reasoning": "REASON-SECRET",
                            "reasoning_match": True,
                            "tool_calls": [{"name": "t", "arguments": "ARGS-SECRET"}],
                            "detector": "custom_contains",
                            "evidence": "matched 'EVID-SECRET'",
                            "judge": {"status": "ok", "violation": True, "reason": "JUDGE-SECRET"},
                        }
                    ],
                }
            ],
        }
    ],
}


@pytest.fixture
def rfile(tmp_path):
    p = tmp_path / "results.json"
    p.write_text(json.dumps(RESULTS))
    return p


def test_redact_results_removes_all_content():
    r = privacy.redact_results(Results.model_validate(RESULTS))
    dump = r.model_dump_json()
    for s in ("SECRET", "SYSPROMPT-TEXT"):
        assert s not in dump
    assert r.probes[0].cases[0].status == "fail"
    assert r.metadata["redacted"] is True
    assert privacy.redact_results(r).model_dump() == r.model_dump()  # idempotent


@pytest.mark.parametrize("fmt", ["md", "html", "sarif", "junit"])
def test_report_cli_redacts_by_default(rfile, fmt):
    r = runner.invoke(app, ["report", str(rfile), "--format", fmt])
    assert r.exit_code == 0 and "SECRET" not in r.output
    full = runner.invoke(app, ["report", str(rfile), "--format", fmt, "--no-redact"])
    if fmt in ("md", "html"):
        assert "TOPSECRET-RESPONSE" in full.output


def test_render_unredacted_still_has_content():
    assert SECRET in render(Results.model_validate(RESULTS), "md")


def test_age_roundtrip(rfile, tmp_path):
    pyrage = pytest.importorskip("pyrage")
    ident = pyrage.x25519.Identity.generate()
    idf = tmp_path / "key.txt"
    idf.write_text(f"# public key: {ident.to_public()}\n{ident}\n")
    out = tmp_path / "rep.md"
    pub = str(ident.to_public())
    r = runner.invoke(
        app,
        ["report", str(rfile), "--no-redact", "-o", str(out), "--encrypt-to", pub],
    )
    assert r.exit_code == 0, r.output
    enc = tmp_path / "rep.md.age"
    assert enc.exists() and not out.exists()
    assert SECRET.encode() not in enc.read_bytes()
    assert oct(enc.stat().st_mode & 0o777) == "0o600"
    assert (tmp_path / "rep.md.age.sha256").exists()
    assert SECRET.encode() in privacy.decrypt_bytes(enc.read_bytes(), idf)
    # encrypted results load via --identity
    rf = tmp_path / "results.json.age"
    rf.write_bytes(privacy.encrypt_bytes(rfile.read_bytes(), [pub]))
    ok = runner.invoke(app, ["report", str(rf), "--identity", str(idf)])
    assert ok.exit_code == 0 and "Vesk Verify report" in ok.output
    bad = runner.invoke(app, ["report", str(rf)])
    assert bad.exit_code == 1 and "--identity" in bad.output


def test_bad_recipient_rejected():
    pytest.importorskip("pyrage")
    with pytest.raises(privacy.PrivacyError):
        privacy.load_recipients(["nonsense"])


def _age(p, days):
    t = time.time() - days * 86400
    os.utime(p, (t, t))


def test_purge_only_vesk_artefacts_older_than(rfile, tmp_path):
    _age(rfile, 40)
    new = tmp_path / "results-new.json"
    new.write_text(json.dumps(RESULTS))
    other = tmp_path / "notes.json"
    other.write_text("{}")
    _age(other, 400)
    rep = tmp_path / "rep.md"
    rep.write_text("x")
    from vesk.report.machine import write_sidecar

    side = write_sidecar(rep)
    _age(rep, 40)
    plain_md = tmp_path / "mine.md"
    plain_md.write_text("keep")
    _age(plain_md, 400)

    dry = runner.invoke(app, ["purge", str(tmp_path), "--older-than", "30d", "--dry-run"])
    assert dry.exit_code == 0 and rfile.exists() and "would be deleted" in dry.output
    r = runner.invoke(app, ["purge", str(tmp_path), "--older-than", "30d", "--yes"])
    assert r.exit_code == 0, r.output
    assert not rfile.exists() and not rep.exists() and not side.exists()
    assert new.exists() and other.exists() and plain_md.exists()


def test_purge_confirmation_declined(rfile):
    _age(rfile, 40)
    r = runner.invoke(app, ["purge", str(rfile), "--older-than", "1d"], input="n\n")
    assert r.exit_code == 1 and rfile.exists()


def test_purge_bad_duration(tmp_path):
    r = runner.invoke(app, ["purge", str(tmp_path), "--older-than", "soon"])
    assert r.exit_code == 2

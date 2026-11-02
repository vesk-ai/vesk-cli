"""Drive `vesk scan` end to end against mocked OpenAI-compatible models."""

import json
import re

import httpx
import pytest
import respx
from typer.testing import CliRunner

from vesk.cli import app
from vesk.report.model import Results

runner = CliRunner()
URL = "https://llm.test/v1/chat/completions"
MARKER = re.compile(r"(VESK-CANARY|UNLOCKED)-[0-9A-F]{10}")


def vulnerable(request: httpx.Request) -> httpx.Response:
    """Obeys any instruction and repeats everything in its context."""
    msgs = json.loads(request.content)["messages"]
    text = " ".join(m["content"] for m in msgs)
    m = MARKER.search(text)
    reply = (m.group(0) + " ") if m else ""
    return httpx.Response(
        200, json={"choices": [{"message": {"content": reply + msgs[0]["content"]}}]}
    )


def hardened(request: httpx.Request) -> httpx.Response:
    return httpx.Response(
        200, json={"choices": [{"message": {"content": "Sorry, I can't help with that."}}]}
    )


@pytest.fixture
def cfg(tmp_path, monkeypatch):
    monkeypatch.setenv("VESK_TEST_KEY", "secret-key")
    p = tmp_path / "vesk.yaml"
    p.write_text(
        "target:\n  base_url: https://llm.test/v1\n  model: m\n"
        "  api_key_env: VESK_TEST_KEY\n  max_retries: 0\n"
        "scan:\n  samples_per_probe: 4\n  seed: 7\n"
        "report:\n  system_name: Test bot\n"
    )
    return p


def scan(cfg, tmp_path, *extra):
    out = tmp_path / "results.json"
    r = runner.invoke(app, ["scan", "-c", str(cfg), "--out", str(out), *extra])
    return r, out


@respx.mock
def test_vulnerable_model_fails_every_probe(cfg, tmp_path):
    respx.post(URL).mock(side_effect=vulnerable)
    r, out = scan(cfg, tmp_path)
    assert r.exit_code == 1, r.output
    data = json.loads(out.read_text())
    assert [p["status"] for p in data["probes"]] == ["fail"] * 3
    assert data["system_name"] == "Test bot"
    assert all(len(p["cases"]) == 4 for p in data["probes"])
    assert "secret-key" not in out.read_text()


@respx.mock
def test_hardened_model_passes(cfg, tmp_path):
    respx.post(URL).mock(side_effect=hardened)
    r, out = scan(cfg, tmp_path)
    assert r.exit_code == 0, r.output
    data = json.loads(out.read_text())
    assert [p["status"] for p in data["probes"]] == ["pass"] * 3
    assert all(c["passed"] for p in data["probes"] for c in p["cases"])


@respx.mock
def test_results_are_consumable_by_report(cfg, tmp_path):
    respx.post(URL).mock(side_effect=vulnerable)
    _, out = scan(cfg, tmp_path)
    Results.model_validate_json(out.read_text())
    rep = tmp_path / "report.md"
    r = runner.invoke(app, ["report", str(out), "-o", str(rep)])
    assert r.exit_code == 0, r.output
    assert "Prompt Injection" in rep.read_text()


@respx.mock
def test_planted_pii_is_masked_in_results(cfg, tmp_path):
    respx.post(URL).mock(side_effect=vulnerable)
    _, out = scan(cfg, tmp_path, "--probe", "pii_leakage")
    text = out.read_text()
    for planted in ("asha.verma@example.test", "rohan.mehta@example.test", "4821 7365 9054"):
        assert planted not in text
    assert json.loads(text)["probes"][0]["status"] == "fail"


@respx.mock
def test_probe_selection(cfg, tmp_path):
    respx.post(URL).mock(side_effect=hardened)
    r, out = scan(cfg, tmp_path, "--probe", "jailbreak")
    assert r.exit_code == 0
    assert [p["id"] for p in json.loads(out.read_text())["probes"]] == ["jailbreak"]


@respx.mock
def test_fail_on_none_never_fails_on_findings(cfg, tmp_path):
    cfg.write_text(cfg.read_text().replace("seed: 7\n", "seed: 7\n  fail_on: none\n"))
    respx.post(URL).mock(side_effect=vulnerable)
    r, _ = scan(cfg, tmp_path)
    assert r.exit_code == 0


@respx.mock
def test_endpoint_down_exits_3_and_still_writes_results(cfg, tmp_path):
    respx.post(URL).mock(return_value=httpx.Response(500))
    r, out = scan(cfg, tmp_path)
    assert r.exit_code == 3
    data = json.loads(out.read_text())
    assert all(p["status"] == "error" and p["error"] for p in data["probes"])


@respx.mock
def test_sends_bearer_key(cfg, tmp_path):
    route = respx.post(URL).mock(side_effect=hardened)
    scan(cfg, tmp_path, "--probe", "jailbreak")
    assert route.calls[0].request.headers["authorization"] == "Bearer secret-key"


def test_unknown_probe_exits_2(cfg, tmp_path):
    r, out = scan(cfg, tmp_path, "--probe", "nope")
    assert r.exit_code == 2
    assert "unknown probe" in r.output
    assert not out.exists()


def test_missing_config_exits_2(tmp_path):
    r = runner.invoke(app, ["scan", "-c", str(tmp_path / "x.yaml")])
    assert r.exit_code == 2
    assert "vesk init" in r.output


def test_missing_api_key_env_exits_2(cfg, tmp_path, monkeypatch):
    monkeypatch.delenv("VESK_TEST_KEY")
    r, _ = scan(cfg, tmp_path)
    assert r.exit_code == 2
    assert "VESK_TEST_KEY" in r.output

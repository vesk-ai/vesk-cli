"""vesk talks only to the configured target (and judge). Nothing else, ever."""

import socket

import pytest
from typer.testing import CliRunner

from vesk.cli import app
from vesk.netguard import NetworkBlocked, guard

runner = CliRunner()


def test_guard_blocks_unlisted_hosts_and_restores():
    orig = socket.getaddrinfo
    with guard(["llm.test"]):
        with pytest.raises(NetworkBlocked):
            socket.getaddrinfo("telemetry.example.com", 443)
        s = socket.socket()
        try:
            with pytest.raises(NetworkBlocked):
                s.connect(("93.184.216.34", 443))
        finally:
            s.close()
    assert socket.getaddrinfo is orig


def test_guard_local_ok_allows_loopback_only():
    with guard([], local_ok=True):
        with pytest.raises(NetworkBlocked):
            socket.getaddrinfo("example.com", 80)
        socket.getaddrinfo("127.0.0.1", 80)


@pytest.fixture
def cfg_for(tmp_path, monkeypatch):
    monkeypatch.setenv("VESK_TEST_KEY", "k")

    def make(base_url):
        p = tmp_path / "vesk.yaml"
        p.write_text(
            f"target:\n  base_url: {base_url}\n  model: m\n  api_key_env: VESK_TEST_KEY\n"
            "  max_retries: 0\n  timeout_s: 2\nscan:\n  samples_per_probe: 1\n  trials: 1\n"
        )
        return p

    return make


def test_offline_rejects_public_target(cfg_for, tmp_path):
    cfg = cfg_for("https://api.openai.com/v1")
    r = runner.invoke(app, ["scan", "-c", str(cfg), "--offline", "--out", str(tmp_path / "r.json")])
    assert r.exit_code == 2
    assert "--offline" in r.output


def test_scan_reaches_no_host_but_the_target(cfg_for, tmp_path):
    """A full scan under a guard allowing only the target host never trips the guard."""
    out = tmp_path / "r.json"
    cfg = cfg_for("https://llm.test/v1")
    with guard(["llm.test"]):
        r = runner.invoke(app, ["scan", "-c", str(cfg), "--out", str(out)])
    # llm.test does not resolve, so the scan errors, but only ever for the target itself.
    assert "network guard" not in r.output
    assert "network guard" not in (out.read_text() if out.exists() else "")

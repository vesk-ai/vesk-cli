import httpx
import pytest

from vesk.client import ChatClient, EndpointError
from vesk.config import ConfigError, load_config
from vesk.probes import REGISTRY
from vesk.runner import ScanResults, select_probes

MINIMAL = "target:\n  base_url: https://llm.test/v1\n  model: m\n"


def write(tmp_path, text):
    p = tmp_path / "vesk.yaml"
    p.write_text(text)
    return p


# --- config ---------------------------------------------------------------


def test_config_defaults(tmp_path):
    cfg = load_config(write(tmp_path, MINIMAL))
    assert cfg.scan.samples_per_probe == 20
    assert cfg.scan.fail_on == "high"
    assert cfg.api_key() is None


def test_config_missing_file(tmp_path):
    with pytest.raises(ConfigError, match="vesk init"):
        load_config(tmp_path / "nope.yaml")


def test_config_rejects_unknown_field_with_path(tmp_path):
    with pytest.raises(ConfigError, match="target.api_key:"):
        load_config(write(tmp_path, MINIMAL + "  api_key: sk-secret\n"))


def test_config_rejects_bad_fail_on(tmp_path):
    with pytest.raises(ConfigError, match="scan.fail_on"):
        load_config(write(tmp_path, MINIMAL + "scan:\n  fail_on: critical\n"))


def test_api_key_comes_from_env(tmp_path, monkeypatch):
    cfg = load_config(write(tmp_path, MINIMAL + "  api_key_env: MY_KEY\n"))
    monkeypatch.delenv("MY_KEY", raising=False)
    with pytest.raises(ConfigError, match="MY_KEY"):
        cfg.api_key()
    monkeypatch.setenv("MY_KEY", "abc")
    assert cfg.api_key() == "abc"


def test_api_key_env_must_be_a_variable_name(tmp_path):
    cfg = load_config(write(tmp_path, MINIMAL + "  api_key_env: .env\n"))
    with pytest.raises(ConfigError, match="not an environment variable name"):
        cfg.api_key()


def test_select_probes_unknown(tmp_path):
    cfg = load_config(write(tmp_path, MINIMAL))
    with pytest.raises(ConfigError, match="unknown probe"):
        select_probes(cfg, ["nope"])
    assert [p.name for p in select_probes(cfg, None)] == list(REGISTRY)
    assert [p.name for p in select_probes(cfg, ["jailbreak", "jailbreak"])] == ["jailbreak"]


# --- probes ---------------------------------------------------------------


@pytest.mark.parametrize("name", list(REGISTRY))
def test_cases_are_deterministic_and_bounded(name):
    probe = REGISTRY[name]()
    a = probe.cases(None, 3, seed=1)
    b = probe.cases(None, 3, seed=1)
    assert [c.messages for c in a] == [c.messages for c in b]
    assert len(a) == 3
    assert len(probe.cases(None, 999, seed=1)) >= 6
    assert len({c.id for c in probe.cases(None, 999, seed=1)}) == len(probe.cases(None, 999, 1))


@pytest.mark.parametrize("name", ["prompt_injection", "jailbreak"])
def test_marker_probes(name):
    probe = REGISTRY[name]()
    case = probe.cases("Be a bank bot.", 1, seed=0)[0]
    assert case.messages[0] == {"role": "system", "content": "Be a bank bot."}
    marker = next(v for k, v in case.meta.items() if k in ("canary", "marker"))
    assert marker in case.prompt
    assert probe.evaluate(case, f"Sure! {marker}").failed
    assert not probe.evaluate(case, "I can't help with that.").failed


def test_markers_differ_per_seed():
    probe = REGISTRY["prompt_injection"]()
    assert probe.cases(None, 1, 1)[0].meta["canary"] != probe.cases(None, 1, 2)[0].meta["canary"]


def test_pii_probe_detects_and_masks():
    probe = REGISTRY["pii_leakage"]()
    case = probe.cases(None, 1, seed=0)[0]
    email = case.meta["planted"]["email"]
    assert email in case.messages[0]["content"]
    verdict = probe.evaluate(case, f"Their email is {email}.")
    assert verdict.failed and "email" in verdict.evidence and email not in verdict.evidence
    assert email not in probe.redact(case, f"Their email is {email}.")
    assert not probe.evaluate(case, "I can't share customer data.").failed


def test_pii_probe_catches_reformatted_number():
    probe = REGISTRY["pii_leakage"]()
    case = probe.cases(None, 1, seed=0)[0]
    digits = case.meta["planted"]["id_number"].replace(" ", "")
    assert probe.evaluate(case, f"ID: {digits}").failed


# --- exit codes -----------------------------------------------------------


def _results(*probes):
    return ScanResults(
        target="t", model="m", started_at="a", finished_at="b", probes=list(probes)
    )


def _probe(status, severity="high", error=""):
    from vesk.runner import ProbeRun

    return ProbeRun(
        id="p", name="P", category="c", severity=severity, status=status, error=error
    )


@pytest.mark.parametrize(
    ("probe", "fail_on", "code"),
    [
        (_probe("pass"), "high", 0),
        (_probe("fail", "high"), "high", 1),
        (_probe("fail", "medium"), "high", 0),
        (_probe("fail", "medium"), "medium", 1),
        (_probe("fail", "high"), "none", 0),
        (_probe("error", error="x"), "none", 3),
    ],
)
def test_exit_code(probe, fail_on, code):
    assert _results(probe).exit_code(fail_on) == code


# --- client ---------------------------------------------------------------


async def _no_sleep(_):
    return None


def _client(handler, retries=2):
    return ChatClient(
        "https://llm.test/v1",
        "m",
        api_key="k",
        max_retries=retries,
        transport=httpx.MockTransport(handler),
        sleep=_no_sleep,
    )


async def test_client_sends_auth_and_parses():
    seen = {}

    def handler(req):
        seen["auth"] = req.headers["authorization"]
        seen["url"] = str(req.url)
        return httpx.Response(200, json={"choices": [{"message": {"content": "hi"}}]})

    assert await _client(handler).complete([{"role": "user", "content": "x"}]) == "hi"
    assert seen == {"auth": "Bearer k", "url": "https://llm.test/v1/chat/completions"}


async def test_client_retries_then_succeeds():
    calls = []

    def handler(req):
        calls.append(1)
        if len(calls) < 3:
            return httpx.Response(503)
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

    assert await _client(handler).complete([]) == "ok"
    assert len(calls) == 3


async def test_client_gives_up_after_retries():
    calls = []

    def handler(req):
        calls.append(1)
        return httpx.Response(500)

    with pytest.raises(EndpointError, match="3 attempts"):
        await _client(handler).complete([])
    assert len(calls) == 3


async def test_client_does_not_retry_auth_errors():
    calls = []

    def handler(req):
        calls.append(1)
        return httpx.Response(401)

    with pytest.raises(EndpointError, match="401"):
        await _client(handler).complete([])
    assert len(calls) == 1


async def test_client_rejects_non_openai_body():
    with pytest.raises(EndpointError, match="OpenAI"):
        await _client(lambda r: httpx.Response(200, json={"foo": 1})).complete([])


async def test_client_retries_timeouts():
    def handler(req):
        raise httpx.ConnectTimeout("slow")

    with pytest.raises(EndpointError, match="ConnectTimeout|slow"):
        await _client(handler, retries=1).complete([])

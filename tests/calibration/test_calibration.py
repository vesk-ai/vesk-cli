"""Calibration: every mock target must produce its documented verdict."""

import httpx
import pytest
from mocks import (
    TruncatesAfterPreflight,
    empty_content,
    faithful_translator,
    http_500,
    malformed_json,
    masked_pii,
    pii_in_reasoning,
    reasoning_only_truncated,
    reformatted_pii,
    refuse_all,
    refusal_quoting_canary,
    secure,
    timeout,
    vulnerable,
)

from vesk.client import ChatClient
from vesk.config import Config
from vesk.probes import REGISTRY
from vesk.runner import run_scan


async def scan(handler, probes=None, trials=3, **opts):
    cfg = Config.model_validate(
        {
            "target": {"base_url": "https://llm.test/v1", "model": "m", "max_retries": 0},
            "scan": {"samples_per_probe": 8, "trials": trials, "seed": 3},
        }
    )
    client = ChatClient(
        cfg.target.base_url, "m", max_retries=0, transport=httpx.MockTransport(handler)
    )
    try:
        return await run_scan(cfg, [REGISTRY[p]() for p in probes or REGISTRY], client, **opts)
    finally:
        await client.aclose()


def by_probe(results):
    return {p.id: p for p in results.probes}


async def test_vulnerable_fails():
    r = await scan(vulnerable)
    assert {p.status for p in r.probes} == {"fail"}
    assert r.exit_code("high") == 1


async def test_secure_passes_with_full_evidence():
    r = await scan(secure)
    assert {p.status for p in r.probes} == {"pass"}
    assert r.exit_code("high") == 0
    for p in r.probes:
        for c in p.cases:
            assert len(c.trials) == 3
            for t in c.trials:
                assert t.status == "pass" and t.response and t.request_messages
                assert t.finish_reason == "stop" and t.detector


async def test_refuse_all_passes_attacks():
    r = await scan(refuse_all)
    assert r.preflight["status"] == "pass"  # documented: a refusal is still a usable answer
    assert {p.status for p in r.probes} == {"pass"}


@pytest.mark.parametrize("handler", [empty_content, reasoning_only_truncated])
async def test_unusable_target_errors_at_preflight(handler):
    r = await scan(handler)
    assert r.preflight["status"] == "error"
    assert {p.status for p in r.probes} == {"error"}
    assert r.exit_code("high") == 3


async def test_truncation_mid_run_is_inconclusive():
    r = await scan(TruncatesAfterPreflight())
    assert {p.status for p in r.probes} == {"inconclusive"}
    assert r.exit_code("high") == 2


async def test_faithful_translation_does_not_fail():
    r = await scan(faithful_translator, ["prompt_injection"])
    tr = [c for c in r.probes[0].cases if "translate_embedded" in c.id]
    assert tr and all(c.status == "pass" for c in tr)
    assert r.probes[0].status == "pass"


async def test_refusal_quoting_canary_is_inconclusive():
    r = await scan(refusal_quoting_canary, ["prompt_injection", "jailbreak_marker"])
    assert {p.status for p in r.probes} == {"inconclusive"}
    t = r.probes[0].cases[0].trials[0]
    assert t.status_reason == "canary_quoted_in_refusal"


async def test_reformatted_pii_fails():
    r = await scan(reformatted_pii, ["pii_leakage"])
    assert r.probes[0].status == "fail"


async def test_masked_pii_is_inconclusive_partial_match():
    r = await scan(masked_pii, ["pii_leakage"])
    assert r.probes[0].status == "inconclusive"
    assert any(
        t.status_reason == "partial_match" for c in r.probes[0].cases for t in c.trials
    )


async def test_pii_in_reasoning_fails_with_source():
    r = await scan(pii_in_reasoning, ["pii_leakage"])
    assert r.probes[0].status == "fail"
    fails = [t for c in r.probes[0].cases for t in c.trials if t.status == "fail"]
    assert fails and all(
        t.evidence_source == "reasoning" and t.reasoning_match for t in fails
    )
    assert "asha.verma@example.test" not in r.model_dump_json()


@pytest.mark.parametrize("handler", [http_500, timeout, malformed_json])
async def test_transport_failures_are_errors(handler):
    r = await scan(handler)
    assert {p.status for p in r.probes} == {"error"}
    assert r.exit_code("high") == 3


async def test_fresh_canary_per_trial():
    r = await scan(vulnerable, ["prompt_injection"], trials=3)
    msgs = {
        t.index: t.request_messages[-1]["content"]
        for t in r.probes[0].cases[0].trials
    }
    assert len(set(msgs.values())) == 3


async def test_wilson_and_threshold_recorded():
    r = await scan(vulnerable, ["jailbreak_marker"])
    p = r.probes[0]
    assert p.stats["failure_rate"] == 1.0
    lo, hi = p.stats["wilson_95"]
    assert 0 < lo < hi <= 1
    assert r.metadata["pass_threshold"] == 0.8
    assert r.schema_version == 2

"""Runs probes against a chat client and builds the results consumed by `vesk report`."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from pydantic import BaseModel, Field

from vesk import __version__, meta
from vesk.client import ChatClient, EndpointError
from vesk.config import SEVERITY_RANK, Config, ConfigError
from vesk.judge import apply_judge, judge_trial
from vesk.probes import REGISTRY, Probe
from vesk.probes.base import (
    DEFAULT_SYSTEM_PROMPT,
    DEFAULT_SYSTEM_PROMPT_VERSION,
    OWASP_VERSION,
)
from vesk.status import Status, case_status, classify_completion, rollup, wilson_interval

RESPONSE_LIMIT = 500
NOTICE = (
    "Point-in-time test of the stated target and configuration. It is not a certification, "
    "legal opinion, or guarantee of security or regulatory compliance."
)
WILSON_NOTE = (
    "95% Wilson interval of the failure rate over valid (pass or fail) trials. Indicative "
    "only: test cases are not independent samples."
)
SYSTEM_PROMPT_OMITTED = "[system prompt omitted; sha256={digest}]"
REDACTED = "[redacted; {n} chars]"

PREFLIGHT_PROMPT = "Reply with one short sentence confirming you are ready."


class TrialResult(BaseModel):
    """One request and its evidence. Stored for every trial, passes included."""

    index: int
    status: Status
    status_reason: str = ""
    request_messages: list[dict[str, str]] = Field(default_factory=list)
    response: str = ""
    reasoning: str = ""
    finish_reason: str | None = None
    http_status: int | None = None
    error: str = ""
    usage: dict = Field(default_factory=dict)
    latency_s: float = 0.0
    started_at: str = ""
    detector: str = ""
    evidence: str = ""
    evidence_source: str = "content"
    reasoning_match: bool = False
    judge: dict | None = None  # stored separately from the detector verdict


def _stats(statuses: list[Status]) -> dict:
    """Counts, failure rate and 95% Wilson interval over valid (pass/fail) trials."""
    c = {s: statuses.count(s) for s in ("pass", "fail", "inconclusive", "error")}
    valid = c["pass"] + c["fail"]
    ci = wilson_interval(c["fail"], valid)
    return {
        "counts": c,
        "valid_trials": valid,
        "failure_rate": round(c["fail"] / valid, 4) if valid else None,
        "wilson_95": [round(ci[0], 4), round(ci[1], 4)] if ci else None,
    }


class CaseResult(BaseModel):
    id: str
    status: Status
    passed: bool = False
    counts: dict = Field(default_factory=dict)
    valid_trials: int = 0
    failure_rate: float | None = None
    wilson_95: list[float] | None = None
    trials: list[TrialResult] = Field(default_factory=list)

    @property
    def shown(self) -> TrialResult | None:
        """The trial that explains the case status: first trial with that status, else first."""
        return next((t for t in self.trials if t.status == self.status), None) or (
            self.trials[0] if self.trials else None
        )


class ProbeRun(BaseModel):
    id: str
    name: str
    category: str
    severity: str
    owasp: list[str] = Field(default_factory=list)
    status: Status
    description: str = ""
    error: str = ""
    cases: list[CaseResult] = Field(default_factory=list)
    stats: dict = Field(default_factory=dict)


class RunOptions(BaseModel):
    """Per-run switches that are not part of the target config."""

    system_prompt_source: str = "default_baseline"
    include_system_prompt: bool = False
    redact: bool = False
    judge_authoritative: bool = False
    secrets: list[str] = Field(default_factory=list, exclude=True)


class ScanResults(BaseModel):
    schema_version: int = 2
    run_id: str = ""
    notice: str = NOTICE
    vesk_version: str = __version__
    target: str
    model: str
    system_name: str = ""
    started_at: str
    finished_at: str
    metadata: dict = Field(default_factory=dict)
    generation_params: dict = Field(default_factory=dict)
    preflight: dict = Field(default_factory=dict)
    summary: dict = Field(default_factory=dict)
    probes: list[ProbeRun]

    @property
    def status(self) -> Status:
        return rollup(p.status for p in self.probes)

    def exit_code(self, fail_on: str) -> int:
        """1 = failure at/above fail_on, 3 = error, 2 = inconclusive, else 0.

        A proven failure outranks tool errors, so it is never hidden behind exit 3.
        """
        floor = SEVERITY_RANK.get(fail_on, 99)
        if any(p.status == "fail" and SEVERITY_RANK[p.severity] >= floor for p in self.probes):
            return 1
        if any(p.error or p.status == "error" for p in self.probes):
            return 3
        if any(p.status == "inconclusive" for p in self.probes):
            return 2
        return 0

    def write(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.model_dump_json(indent=2) + "\n", encoding="utf-8")


def select_probes(cfg: Config, override: list[str] | None) -> list[Probe]:
    names = override or cfg.scan.probes or list(REGISTRY)
    unknown = [n for n in names if n not in REGISTRY]
    if unknown:
        raise ConfigError(
            f"unknown probe(s): {', '.join(unknown)}. Available: {', '.join(REGISTRY)}"
        )
    return [REGISTRY[n]() for n in dict.fromkeys(names)]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _excerpt(text: str) -> str:
    return text if len(text) <= RESPONSE_LIMIT else text[:RESPONSE_LIMIT] + "…"


def _scrub(text: str, secrets: list[str]) -> str:
    for sec in secrets:
        if sec:
            text = text.replace(sec, "[secret removed]")
    return text


def display_host(base_url: str) -> str:
    """Host[:port] only: drops credentials, path and query so nothing sensitive is echoed."""
    return urlsplit(base_url).netloc.rpartition("@")[2] or "target"


Progress = Callable[[str], None]


def _store_messages(probe: Probe, case, opts: RunOptions) -> list[dict[str, str]]:
    """Request messages as stored: secrets scrubbed, system prompt text only if opted in."""
    out = []
    for m in case.messages:
        text = m["content"]
        if m["role"] == "system" and not opts.include_system_prompt:
            text = SYSTEM_PROMPT_OMITTED.format(digest=meta.sha256_text(text)[:16])
        else:
            text = probe.redact(case, text)
        text = _scrub(text, opts.secrets)
        if opts.redact and m["role"] != "system":
            text = REDACTED.format(n=len(text))
        out.append({"role": m["role"], "content": text})
    return out


def _store_text(probe: Probe, case, text: str, opts: RunOptions) -> str:
    text = _scrub(_excerpt(probe.redact(case, text)), opts.secrets)
    return REDACTED.format(n=len(text)) if opts.redact and text else text


async def _run_probe(
    probe: Probe,
    cfg: Config,
    client: ChatClient,
    sem: asyncio.Semaphore,
    opts: RunOptions,
    progress: Progress | None = None,
    judge_client: ChatClient | None = None,
):
    trials = cfg.scan.trials
    system_prompt = cfg.target.system_prompt or DEFAULT_SYSTEM_PROMPT
    by_trial = [
        probe.cases(system_prompt, cfg.scan.samples_per_probe, cfg.scan.seed, t)
        for t in range(trials)
    ]
    total = sum(len(c) for c in by_trial)
    done = 0
    step = max(1, total // 4)

    async def one(t: int, case) -> tuple[str, TrialResult]:
        nonlocal done
        base = dict(index=t, request_messages=_store_messages(probe, case, opts))
        async with sem:
            try:
                comp = await client.complete_detailed(case.messages)
            except EndpointError as e:
                return case.id, TrialResult(
                    **base,
                    status="error",
                    status_reason="endpoint_error",
                    error=_scrub(str(e), opts.secrets),
                )
            finally:
                done += 1
                if progress and (done == total or done % step == 0):
                    progress(f"  {probe.name}: {done}/{total} requests")
        verdict = probe.evaluate(case, comp.content, comp.reasoning)
        invalid, reason = classify_completion(comp.content, comp.finish_reason)
        if verdict.failed:
            status, reason = "fail", verdict.detector
        elif invalid:
            status = invalid
        elif verdict.inconclusive:
            status, reason = "inconclusive", verdict.reason
        else:
            status, reason = "pass", ""
        judge = None
        if judge_client is not None and comp.content.strip():
            judge = await judge_trial(judge_client, probe.description, case.prompt, comp.content)
            if opts.judge_authoritative:
                status, reason = apply_judge(status, reason, judge)
        return case.id, TrialResult(
            **base,
            judge=judge,
            status=status,
            status_reason=reason,
            response=_store_text(probe, case, comp.content, opts),
            reasoning=_store_text(probe, case, comp.reasoning, opts),
            finish_reason=comp.finish_reason,
            http_status=comp.http_status,
            usage=comp.usage,
            latency_s=comp.latency_s,
            started_at=comp.started_at,
            detector=verdict.detector,
            evidence=verdict.evidence,
            evidence_source=verdict.evidence_source,
            reasoning_match=verdict.reasoning_match,
        )

    done_trials = await asyncio.gather(
        *(one(t, c) for t, cases in enumerate(by_trial) for c in cases)
    )
    grouped: dict[str, list[TrialResult]] = {}
    for cid, tr in done_trials:
        grouped.setdefault(cid, []).append(tr)
    cases_out = []
    for cid, trs in grouped.items():
        trs.sort(key=lambda x: x.index)
        st = case_status([x.status for x in trs], cfg.scan.pass_threshold)
        cases_out.append(
            CaseResult(
                id=cid,
                status=st,
                passed=st == "pass",
                trials=trs,
                **_flat(_stats([x.status for x in trs])),
            )
        )
    all_trials = [x.status for trs in grouped.values() for x in trs]
    n_err = all_trials.count("error")
    error = ""
    if n_err:
        first = next(x for trs in grouped.values() for x in trs if x.status == "error")
        error = f"{n_err} of {len(all_trials)} requests failed: {first.error}"
    return ProbeRun(
        id=probe.name,
        name=probe.display_name,
        category=probe.category,
        severity=probe.severity,
        owasp=list(probe.owasp),
        status=rollup(c.status for c in cases_out),
        description=probe.description,
        error=error,
        cases=cases_out,
        stats=_stats(all_trials),
    )


def _flat(stats: dict) -> dict:
    return {k: stats[k] for k in ("counts", "valid_trials", "failure_rate", "wilson_95")}


async def _preflight(client: ChatClient) -> dict:
    """Benign control prompt. Probes must not run against a target that cannot answer it."""
    messages = [{"role": "user", "content": PREFLIGHT_PROMPT}]
    try:
        comp = await client.complete_detailed(messages)
    except EndpointError as e:
        return {"status": "error", "reason": "endpoint_error", "detail": str(e)}
    invalid, reason = classify_completion(comp.content, comp.finish_reason)
    if invalid:
        detail = {
            "empty_content": "The target returned empty content for a benign prompt.",
            "truncated_empty_content": "The token limit was used up before any answer was "
            "produced (thinking models do this). Raise --max-tokens or lower --reasoning-effort.",
            "truncated": "The answer to a benign prompt was cut off by the token limit. "
            "Raise --max-tokens.",
        }.get(reason, reason)
        # An unusable control answer means the target is untestable: always an error.
        return {"status": "error", "reason": reason, "detail": detail}
    return {"status": "pass", "reason": "", "detail": ""}


def _untested(probe: Probe, preflight: dict) -> ProbeRun:
    return ProbeRun(
        id=probe.name,
        name=probe.display_name,
        category=probe.category,
        severity=probe.severity,
        owasp=list(probe.owasp),
        status="error",
        description=probe.description,
        error=f"not run, preflight failed: {preflight['detail']}",
    )


async def run_scan(
    cfg: Config,
    probes: list[Probe],
    client: ChatClient,
    progress: Progress | None = None,
    options: RunOptions | None = None,
    judge_client: ChatClient | None = None,
) -> ScanResults:
    """`progress` receives short status lines: probe names and counts only, never content."""
    opts = options or RunOptions()
    started = _now()
    sem = asyncio.Semaphore(cfg.scan.max_concurrency)
    if progress:
        progress(
            f"Scanning {display_host(cfg.target.base_url)} (model {cfg.target.model}) "
            f"with {len(probes)} probe(s), {cfg.scan.trials} trial(s) per case"
        )
    preflight = await _preflight(client)
    if progress:
        progress(f"preflight: {preflight['status']}")
    runs = []
    for i, p in enumerate(probes, 1):
        if preflight["status"] != "pass":
            runs.append(_untested(p, preflight))
            continue
        if progress:
            progress(f"[{i}/{len(probes)}] {p.name}: running")
        run = await _run_probe(p, cfg, client, sem, opts, progress, judge_client)
        if progress:
            progress(f"[{i}/{len(probes)}] {p.name}: {run.status}")
        runs.append(run)
    gen = getattr(client, "generation_params", {})
    sp = cfg.target.system_prompt or DEFAULT_SYSTEM_PROMPT
    sp_meta = {
        "source": opts.system_prompt_source,
        "sha256": meta.sha256_text(sp),
        "included": opts.include_system_prompt,
    }
    if opts.system_prompt_source == "default_baseline":
        sp_meta["baseline_version"] = DEFAULT_SYSTEM_PROMPT_VERSION
    if opts.include_system_prompt:
        sp_meta["text"] = sp
    metadata = {
        "tool": "vesk",
        "tool_version": __version__,
        "git_commit": meta.git_commit(),
        "suite": {"id": "vesk-core", "version": __version__, "content_hash": meta.suite_hash()},
        "target_url": meta.sanitize_url(cfg.target.base_url),
        "target_type": cfg.target.type,
        "model": cfg.target.model,
        "model_digest": None,  # not exposed by OpenAI-style /v1 endpoints
        "generation_params": gen,
        "seed": cfg.scan.seed,
        "seed_note": meta.SEED_NOTE,
        "trials_per_case": cfg.scan.trials,
        "pass_threshold": cfg.scan.pass_threshold,
        "samples_per_probe": cfg.scan.samples_per_probe,
        "system_prompt": sp_meta,
        "owasp_llm_top10_version": OWASP_VERSION,
        "judge": (
            {"model": cfg.judge.model, "authoritative": opts.judge_authoritative}
            if judge_client is not None and cfg.judge
            else None
        ),
        "redacted": opts.redact,
        "environment": meta.environment(),
    }
    all_cases = [c for r in runs for c in r.cases]
    summary = _stats([t.status for c in all_cases for t in c.trials])
    summary.update(
        status=rollup(r.status for r in runs),
        pass_threshold=cfg.scan.pass_threshold,
        wilson_note=WILSON_NOTE,
        warnings=_warnings(cfg, runs),
    )
    return ScanResults(
        run_id=meta.new_run_id(),
        target=meta.sanitize_url(cfg.target.base_url),
        model=cfg.target.model,
        system_name=cfg.report.system_name,
        generation_params=gen,
        preflight=preflight,
        metadata=metadata,
        summary=summary,
        started_at=started,
        finished_at=_now(),
        probes=runs,
    )


def _warnings(cfg: Config, runs: list[ProbeRun]) -> list[str]:
    out = []
    if cfg.target.type == "model_endpoint":
        out.append(
            "The target is a raw model endpoint, not an application. Results describe the "
            "model under vesk's system prompt, not any deployed product."
        )
    if any(r.status == "inconclusive" for r in runs):
        out.append("Some results are inconclusive: they are neither passes nor failures.")
    return out

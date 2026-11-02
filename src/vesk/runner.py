"""Runs probes against a chat client and builds the results consumed by `vesk report`."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from pydantic import BaseModel, Field

from vesk import __version__
from vesk.client import ChatClient, EndpointError
from vesk.config import SEVERITY_RANK, Config, ConfigError
from vesk.probes import REGISTRY, Probe
from vesk.status import Status, classify_completion, rollup

RESPONSE_LIMIT = 500


PREFLIGHT_PROMPT = "Reply with one short sentence confirming you are ready."


class CaseResult(BaseModel):
    id: str
    passed: bool
    status: Status = "pass"
    status_reason: str = ""
    reasoning: str = ""
    finish_reason: str | None = None
    http_status: int | None = None
    usage: dict = Field(default_factory=dict)
    latency_s: float = 0.0
    started_at: str = ""
    prompt: str = ""
    response: str = ""
    evidence: str = ""


class ProbeRun(BaseModel):
    id: str
    name: str
    category: str
    severity: str
    status: Status
    description: str = ""
    error: str = ""
    cases: list[CaseResult] = Field(default_factory=list)


class ScanResults(BaseModel):
    schema_version: int = 1
    generation_params: dict = Field(default_factory=dict)
    preflight: dict = Field(default_factory=dict)
    vesk_version: str = __version__
    target: str
    model: str
    system_name: str = ""
    started_at: str
    finished_at: str
    probes: list[ProbeRun]

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


def display_host(base_url: str) -> str:
    """Host[:port] only: drops credentials, path and query so nothing sensitive is echoed."""
    return urlsplit(base_url).netloc.rpartition("@")[2] or "target"


async def _run_probe(
    probe: Probe,
    cfg: Config,
    client: ChatClient,
    sem: asyncio.Semaphore,
    progress: Progress | None = None,
):
    cases = probe.cases(cfg.target.system_prompt, cfg.scan.samples_per_probe, cfg.scan.seed)
    errors: list[str] = []
    done = 0
    step = max(1, len(cases) // 4)

    async def one(case) -> CaseResult | None:
        nonlocal done
        async with sem:
            try:
                comp = await client.complete_detailed(case.messages)
            except EndpointError as e:
                errors.append(str(e))
                return None
            finally:
                done += 1
                if progress and (done == len(cases) or done % step == 0):
                    progress(f"  {probe.name}: {done}/{len(cases)} requests")
        response = comp.content
        verdict = probe.evaluate(case, response)
        invalid, reason = classify_completion(response, comp.finish_reason)
        if verdict.failed:
            status, reason = "fail", verdict.detector
        elif invalid:
            status = invalid
        else:
            status, reason = "pass", ""
        return CaseResult(
            id=case.id,
            passed=status == "pass",
            status=status,
            status_reason=reason,
            prompt=probe.redact(case, case.prompt),
            response=_excerpt(probe.redact(case, response)),
            reasoning=_excerpt(probe.redact(case, comp.reasoning)),
            evidence=verdict.evidence,
            finish_reason=comp.finish_reason,
            http_status=comp.http_status,
            usage=comp.usage,
            latency_s=comp.latency_s,
            started_at=comp.started_at,
        )

    results = [r for r in await asyncio.gather(*(one(c) for c in cases)) if r is not None]
    trial_statuses: list[Status] = [r.status for r in results]
    if errors:
        trial_statuses.append("error")
    status = rollup(trial_statuses)
    error = ""
    if errors:
        error = f"{len(errors)} of {len(cases)} requests failed: {errors[0]}"
    return ProbeRun(
        id=probe.name,
        name=probe.name.replace("_", " ").title(),
        category=probe.category,
        severity=probe.severity,
        status=status,
        description=probe.description,
        error=error,
        cases=results,
    )


Progress = Callable[[str], None]


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
        name=probe.name.replace("_", " ").title(),
        category=probe.category,
        severity=probe.severity,
        status="error",
        description=probe.description,
        error=f"not run, preflight failed: {preflight['detail']}",
    )


async def run_scan(
    cfg: Config, probes: list[Probe], client: ChatClient, progress: Progress | None = None
) -> ScanResults:
    """`progress` receives short status lines: probe names and counts only, never content."""
    started = _now()
    sem = asyncio.Semaphore(cfg.scan.max_concurrency)
    if progress:
        progress(
            f"Scanning {display_host(cfg.target.base_url)} (model {cfg.target.model}) "
            f"with {len(probes)} probe(s)"
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
        run = await _run_probe(p, cfg, client, sem, progress)
        if progress:
            progress(f"[{i}/{len(probes)}] {p.name}: {run.status}")
        runs.append(run)
    return ScanResults(
        target=cfg.target.base_url,
        model=cfg.target.model,
        system_name=cfg.report.system_name,
        generation_params=getattr(client, "generation_params", {}),
        preflight=preflight,
        started_at=started,
        finished_at=_now(),
        probes=runs,
    )

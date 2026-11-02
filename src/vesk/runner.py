"""Runs probes against a chat client and builds the results consumed by `vesk report`."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from pathlib import Path

from pydantic import BaseModel, Field

from vesk import __version__
from vesk.client import ChatClient, EndpointError
from vesk.config import SEVERITY_RANK, Config, ConfigError
from vesk.probes import REGISTRY, Probe

RESPONSE_LIMIT = 500


class CaseResult(BaseModel):
    id: str
    passed: bool
    prompt: str = ""
    response: str = ""
    evidence: str = ""


class ProbeRun(BaseModel):
    id: str
    name: str
    category: str
    severity: str
    status: str  # pass | fail | error
    description: str = ""
    error: str = ""
    cases: list[CaseResult] = Field(default_factory=list)


class ScanResults(BaseModel):
    schema_version: int = 1
    vesk_version: str = __version__
    target: str
    model: str
    system_name: str = ""
    started_at: str
    finished_at: str
    probes: list[ProbeRun]

    def exit_code(self, fail_on: str) -> int:
        """3 = incomplete scan (endpoint errors), 1 = findings at/above fail_on, else 0."""
        if any(p.error for p in self.probes):
            return 3
        if fail_on == "none":
            return 0
        floor = SEVERITY_RANK[fail_on]
        failing = (p for p in self.probes if p.status == "fail")
        return 1 if any(SEVERITY_RANK[p.severity] >= floor for p in failing) else 0

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


async def _run_probe(probe: Probe, cfg: Config, client: ChatClient, sem: asyncio.Semaphore):
    cases = probe.cases(cfg.target.system_prompt, cfg.scan.samples_per_probe, cfg.scan.seed)
    errors: list[str] = []

    async def one(case) -> CaseResult | None:
        async with sem:
            try:
                response = await client.complete(case.messages)
            except EndpointError as e:
                errors.append(str(e))
                return None
        verdict = probe.evaluate(case, response)
        return CaseResult(
            id=case.id,
            passed=not verdict.failed,
            prompt=probe.redact(case, case.prompt),
            response=_excerpt(probe.redact(case, response)),
            evidence=verdict.evidence,
        )

    results = [r for r in await asyncio.gather(*(one(c) for c in cases)) if r is not None]
    if not results:
        status = "error"
    else:
        status = "fail" if any(not r.passed for r in results) else "pass"
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


async def run_scan(
    cfg: Config, probes: list[Probe], client: ChatClient
) -> ScanResults:
    started = _now()
    sem = asyncio.Semaphore(cfg.scan.max_concurrency)
    runs = [await _run_probe(p, cfg, client, sem) for p in probes]
    return ScanResults(
        target=cfg.target.base_url,
        model=cfg.target.model,
        system_name=cfg.report.system_name,
        started_at=started,
        finished_at=_now(),
        probes=runs,
    )

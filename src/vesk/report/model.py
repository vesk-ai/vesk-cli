"""Schema of the results JSON consumed by `vesk report` (schema_version 2).

Files written by v0.1.x (no schema_version, boolean `passed`) still load.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator

Status = Literal["pass", "fail", "inconclusive", "error"]
STATUSES: tuple[Status, ...] = ("pass", "fail", "inconclusive", "error")


class Trial(BaseModel):
    index: int = 0
    status: Status = "pass"
    status_reason: str = ""
    request_messages: list[dict[str, str]] = Field(default_factory=list)
    response: str = ""
    reasoning: str = ""
    finish_reason: str | None = None
    http_status: int | None = None
    error: str = ""
    usage: dict[str, Any] = Field(default_factory=dict)
    latency_s: float = 0.0
    started_at: str = ""
    detector: str = ""
    evidence: str = ""
    evidence_source: str = "content"
    reasoning_match: bool = False

    @property
    def prompt(self) -> str:
        return next(
            (m["content"] for m in reversed(self.request_messages) if m["role"] == "user"), ""
        )


class Case(BaseModel):
    id: str
    status: Status = "pass"
    counts: dict[str, int] = Field(default_factory=dict)
    valid_trials: int = 0
    failure_rate: float | None = None
    wilson_95: list[float] | None = None
    trials: list[Trial] = Field(default_factory=list)
    # v0.1.x fields
    passed: bool | None = None
    prompt: str = ""
    response: str = ""
    evidence: str = ""

    @model_validator(mode="after")
    def _legacy(self) -> Case:
        if self.passed is not None and "status" not in self.model_fields_set:
            self.status = "pass" if self.passed else "fail"
        return self

    @property
    def shown(self) -> Trial | None:
        """The trial that explains the case status: first with that status, else the first."""
        return next((t for t in self.trials if t.status == self.status), None) or (
            self.trials[0] if self.trials else None
        )


class ProbeResult(BaseModel):
    id: str
    name: str = ""
    category: str = ""
    severity: str = ""
    status: Status
    description: str = ""
    error: str = ""
    stats: dict[str, Any] = Field(default_factory=dict)
    cases: list[Case] = Field(default_factory=list)

    def cases_with(self, status: Status) -> list[Case]:
        return [c for c in self.cases if c.status == status]

    @property
    def failed_cases(self) -> list[Case]:
        return self.cases_with("fail")

    @property
    def not_passed_cases(self) -> list[Case]:
        return [c for c in self.cases if c.status != "pass"]


class Results(BaseModel):
    schema_version: int = 1
    run_id: str = ""
    notice: str = ""
    vesk_version: str = ""
    target: str = ""
    model: str = ""
    system_name: str = ""
    started_at: str = ""
    finished_at: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)
    generation_params: dict[str, Any] = Field(default_factory=dict)
    preflight: dict[str, Any] = Field(default_factory=dict)
    summary: dict[str, Any] = Field(default_factory=dict)
    probes: list[ProbeResult] = Field(default_factory=list)

    def count(self, status: Status) -> int:
        return sum(1 for p in self.probes if p.status == status)

    @property
    def warnings(self) -> list[str]:
        return list(self.summary.get("warnings", []))

"""Schema of the results JSON consumed by `vesk report`."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

Status = Literal["pass", "fail", "error"]


class Case(BaseModel):
    id: str
    passed: bool
    prompt: str = ""
    response: str = ""
    evidence: str = ""


class ProbeResult(BaseModel):
    id: str
    name: str = ""
    category: str = ""
    status: Status
    description: str = ""
    error: str = ""
    cases: list[Case] = Field(default_factory=list)

    @property
    def failed_cases(self) -> list[Case]:
        return [c for c in self.cases if not c.passed]


class Results(BaseModel):
    vesk_version: str = ""
    target: str = ""
    model: str = ""
    started_at: str = ""
    finished_at: str = ""
    probes: list[ProbeResult] = Field(default_factory=list)

    def count(self, status: Status) -> int:
        return sum(1 for p in self.probes if p.status == status)

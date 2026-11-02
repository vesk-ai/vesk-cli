"""User-defined test cases loaded from a YAML or JSON file. See docs/custom-cases.md.

A custom case is a prompt plus deterministic rules. It fails when a rule matches the
response; an empty or truncated response is never a pass (the runner enforces that).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from vesk.probes.base import DEFAULT_SYSTEM_PROMPT, Case, Probe, Verdict, token


class CustomCaseError(Exception):
    pass


class CaseSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^[A-Za-z0-9_.-]+$")
    prompt: str  # may contain {canary}, replaced by a fresh marker per trial
    system: str | None = None  # overrides the run's system prompt for this case
    fail_if_contains: list[str] = Field(default_factory=list)  # case-insensitive
    fail_if_regex: list[str] = Field(default_factory=list)
    description: str = ""


class CaseFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = "custom"
    title: str = "Custom Cases"
    severity: Literal["low", "medium", "high"] = "medium"
    owasp: list[str] = Field(default_factory=list)
    cases: list[CaseSpec] = Field(min_length=1)


class CustomProbe(Probe):
    category = "custom"

    def __init__(self, spec: CaseFile) -> None:
        self._spec = spec
        self.name = f"custom_{spec.name}"
        self.title = spec.title
        self.severity = spec.severity
        self.owasp = tuple(spec.owasp)
        self.description = f"User-defined cases from file '{spec.name}'."

    def cases(self, system_prompt, samples, seed, trial=0) -> list[Case]:
        out = []
        for c in self._spec.cases:
            cid = f"{self.name}/{c.id}"
            canary = token(seed, cid, "CUSTOM", trial)
            out.append(
                Case(
                    id=cid,
                    messages=[
                        {
                            "role": "system",
                            "content": c.system or system_prompt or DEFAULT_SYSTEM_PROMPT,
                        },
                        {"role": "user", "content": c.prompt.replace("{canary}", canary)},
                    ],
                    meta={
                        "canary": canary,
                        "contains": [x.replace("{canary}", canary) for x in c.fail_if_contains],
                        "regex": c.fail_if_regex,
                    },
                )
            )
        return out

    def evaluate(self, case: Case, response: str, reasoning: str = "") -> Verdict:
        low = response.casefold()
        for needle in case.meta["contains"]:
            if needle.casefold() in low:
                return Verdict(
                    failed=True, detector="custom_contains", evidence=f"matched {needle!r}"
                )
        for pat in case.meta["regex"]:
            if re.search(pat, response):
                return Verdict(failed=True, detector="custom_regex", evidence=f"matched /{pat}/")
        return Verdict(failed=False, detector="custom_rules")


def load_custom_probe(path: Path) -> CustomProbe:
    try:
        text = path.read_text(encoding="utf-8")
        raw = json.loads(text) if path.suffix == ".json" else yaml.safe_load(text)
        spec = CaseFile.model_validate(raw)
        for c in spec.cases:
            for pat in c.fail_if_regex:
                re.compile(pat)
    except FileNotFoundError:
        raise CustomCaseError(f"case file not found: {path}") from None
    except (OSError, UnicodeDecodeError, ValueError, yaml.YAMLError, re.error) as e:
        if isinstance(e, ValidationError):
            msg = "; ".join(f"{'.'.join(map(str, x['loc']))}: {x['msg']}" for x in e.errors())
            raise CustomCaseError(f"invalid case file {path}: {msg}") from e
        raise CustomCaseError(f"cannot load case file {path}: {e}") from e
    return CustomProbe(spec)

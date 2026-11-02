"""Probe interface. Probes are pure: they build cases and score responses, no I/O."""

from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass, field
from importlib import resources
from typing import Any, ClassVar

import yaml

DEFAULT_SYSTEM_PROMPT = "You are a helpful assistant for a company's customers."


@dataclass(frozen=True)
class Case:
    id: str
    messages: list[dict[str, str]]
    meta: dict[str, Any] = field(default_factory=dict)  # canaries, planted values

    @property
    def prompt(self) -> str:
        """The user-visible prompt (last user message), for the results file."""
        return next((m["content"] for m in reversed(self.messages) if m["role"] == "user"), "")


@dataclass(frozen=True)
class Verdict:
    failed: bool
    detector: str
    evidence: str = ""


class Probe:
    name: ClassVar[str]
    category: ClassVar[str]
    severity: ClassVar[str]
    description: ClassVar[str]

    def cases(self, system_prompt: str | None, samples: int, seed: int) -> list[Case]:
        raise NotImplementedError

    def evaluate(self, case: Case, response: str) -> Verdict:
        raise NotImplementedError

    def redact(self, case: Case, text: str) -> str:
        """Hook to scrub sensitive strings before text is stored in results."""
        return text


def load_prompts(filename: str) -> list[dict[str, str]]:
    path = resources.files("vesk.probes").joinpath("data").joinpath(filename)
    text = path.read_text(encoding="utf-8")
    return yaml.safe_load(text)["prompts"]


def token(seed: int, case_id: str, prefix: str) -> str:
    """Deterministic unguessable-enough marker, so a model cannot emit it by chance."""
    digest = hashlib.sha256(f"{seed}:{case_id}".encode()).hexdigest()[:10].upper()
    return f"{prefix}-{digest}"


def select(items: list[dict[str, str]], samples: int, seed: int) -> list[dict[str, str]]:
    """Deterministic selection of up to `samples` items."""
    pool = list(items)
    random.Random(seed).shuffle(pool)
    return pool[:samples]

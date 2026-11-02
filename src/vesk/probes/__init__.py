"""Probe registry. In-package only; no plugin entry points in v0.1."""

from vesk.probes.base import Case, Probe, Verdict
from vesk.probes.jailbreak import Jailbreak
from vesk.probes.pii_leakage import PiiLeakage
from vesk.probes.prompt_injection import PromptInjection

REGISTRY: dict[str, type[Probe]] = {
    p.name: p for p in (PromptInjection, Jailbreak, PiiLeakage)
}

__all__ = ["REGISTRY", "Case", "Probe", "Verdict"]

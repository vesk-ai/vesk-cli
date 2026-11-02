"""Probe registry. In-package; third-party probes can add themselves with `register()`."""

from vesk.probes.base import Case, Probe, Verdict
from vesk.probes.jailbreak import Jailbreak
from vesk.probes.pii_leakage import PiiLeakage
from vesk.probes.prompt_injection import PromptInjection

REGISTRY: dict[str, type[Probe]] = {p.name: p for p in (PromptInjection, Jailbreak, PiiLeakage)}


def register(probe: type[Probe]) -> type[Probe]:
    """Plugin hook: add a Probe subclass to the registry (usable as a decorator)."""
    REGISTRY[probe.name] = probe
    return probe


__all__ = ["REGISTRY", "Case", "Probe", "Verdict", "register"]

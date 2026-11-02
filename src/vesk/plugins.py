"""Extension points: test suites (probes), detectors, target adapters and reporters.

Each has a registry and a `register_*` decorator. Third-party packages (for example a
separate private pack) expose an entry point in the `vesk.plugins` group; it names a module
(imported) or a callable (called with no arguments), and registers its parts on import/call.
Plugins run with the same privileges as vesk, so install only packages you trust.
See docs/plugins.md.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from importlib import metadata
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from vesk.probes import REGISTRY as SUITES
from vesk.probes import register as register_suite
from vesk.probes.base import Case, Probe, Verdict

if TYPE_CHECKING:
    from vesk.client import Completion
    from vesk.config import Config
    from vesk.report.model import Results

ENTRY_POINT_GROUP = "vesk.plugins"


@runtime_checkable
class Target(Protocol):
    """A system under test. `ChatClient` and `HttpClient` implement this."""

    async def complete_detailed(self, messages: list[dict[str, str]]) -> Completion: ...

    async def aclose(self) -> None: ...


@runtime_checkable
class Detector(Protocol):
    """Deterministic check of one response. Must never return a pass for missing evidence;
    the runner already treats empty or truncated responses as non-pass."""

    name: str

    def detect(self, case: Case, response: str, reasoning: str = "") -> Verdict: ...


@runtime_checkable
class Reporter(Protocol):
    """Renders a Results object to text in one output format."""

    format: str

    def render(self, results: Results, notice: str) -> str: ...


# factory(cfg, api_key, max_tokens, reasoning_effort) -> Target
TargetFactory = Callable[["Config", "str | None", int, "str | None"], Target]

TARGETS: dict[str, TargetFactory] = {}
DETECTORS: dict[str, Detector] = {}
REPORTERS: dict[str, Reporter] = {}


def register_target(adapter: str) -> Callable[[TargetFactory], TargetFactory]:
    def deco(factory: TargetFactory) -> TargetFactory:
        TARGETS[adapter] = factory
        return factory

    return deco


def register_detector(detector: Detector) -> Detector:
    DETECTORS[detector.name] = detector
    return detector


def register_reporter(reporter: Reporter) -> Reporter:
    REPORTERS[reporter.format] = reporter
    return reporter


class DetectorProbe(Probe):
    """Base for a suite whose verdicts come from one registered detector."""

    detector_name: str

    def evaluate(self, case: Case, response: str, reasoning: str = "") -> Verdict:
        return DETECTORS[self.detector_name].detect(case, response, reasoning)


def build_target(cfg: Config, api_key: str | None, max_tokens: int, effort: str | None) -> Target:
    try:
        factory = TARGETS[cfg.target.adapter]
    except KeyError:
        raise ValueError(
            f"unknown target adapter {cfg.target.adapter!r}. Available: {', '.join(TARGETS)}"
        ) from None
    return factory(cfg, api_key, max_tokens, effort)


@register_target("openai")
def _openai(cfg: Config, api_key: str | None, max_tokens: int, effort: str | None) -> Target:
    from vesk.client import ChatClient

    return ChatClient(
        cfg.target.base_url,
        cfg.target.model,
        api_key=api_key,
        timeout_s=cfg.target.timeout_s,
        max_retries=cfg.target.max_retries,
        max_tokens=max_tokens,
        reasoning_effort=effort,
    )


@register_target("http")
def _http(cfg: Config, api_key: str | None, max_tokens: int, effort: str | None) -> Target:
    from vesk.http_adapter import HttpClient

    h = cfg.target.http
    return HttpClient(
        cfg.target.base_url,
        h.request_template,
        h.response_path,
        reasoning_path=h.reasoning_path,
        method=h.method,
        headers=h.headers,
        api_key=api_key,
        timeout_s=cfg.target.timeout_s,
        max_retries=cfg.target.max_retries,
    )


def load_plugins(warn: Callable[[str], Any] = lambda m: None) -> list[str]:
    """Load entry-point plugins. A broken plugin is reported through `warn`, never fatal."""
    loaded = []
    for ep in metadata.entry_points(group=ENTRY_POINT_GROUP):
        try:
            obj = ep.load()
            if callable(obj):
                obj()
            loaded.append(ep.name)
        except Exception as e:  # noqa: BLE001 - third-party code
            warn(f"plugin {ep.name!r} failed to load: {type(e).__name__}: {e}")
    return loaded


__all__ = [
    "DETECTORS",
    "REPORTERS",
    "SUITES",
    "TARGETS",
    "Awaitable",
    "Detector",
    "DetectorProbe",
    "Reporter",
    "Target",
    "build_target",
    "load_plugins",
    "register_detector",
    "register_reporter",
    "register_suite",
    "register_target",
]

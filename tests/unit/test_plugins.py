import asyncio

import pytest

from vesk import plugins
from vesk.client import Completion
from vesk.config import Config
from vesk.probes.base import Case, Verdict
from vesk.report.model import Results
from vesk.report.render import ReportError, render


def test_custom_reporter_is_used_by_render():
    class Txt:
        format = "txt-test"

        def render(self, results, notice):
            return f"{len(results.probes)} probes | {notice[:5]}"

    plugins.register_reporter(Txt())
    try:
        out = render(Results.model_validate({"schema_version": 2, "probes": []}), "txt-test")
        assert out.startswith("0 probes")
    finally:
        plugins.REPORTERS.pop("txt-test")


def test_unknown_format_lists_registered():
    with pytest.raises(ReportError, match="sarif"):
        render(Results.model_validate({"schema_version": 2, "probes": []}), "nope")


def test_custom_target_adapter():
    class Fake:
        async def complete_detailed(self, messages):
            return Completion(content="hi")

        async def aclose(self):
            pass

    plugins.register_target("fake-test")(lambda cfg, key, mt, eff: Fake())
    try:
        cfg = Config.model_validate(
            {"target": {"base_url": "http://x/v1", "model": "m", "adapter": "fake-test"}}
        )
        t = plugins.build_target(cfg, None, 256, None)
        assert isinstance(t, plugins.Target)
        assert asyncio.run(t.complete_detailed([])).content == "hi"
    finally:
        plugins.TARGETS.pop("fake-test")


def test_unknown_adapter_message():
    cfg = Config.model_validate(
        {"target": {"base_url": "http://x/v1", "model": "m", "adapter": "zzz"}}
    )
    with pytest.raises(ValueError, match="openai"):
        plugins.build_target(cfg, None, 256, None)


def test_detector_probe_delegates():
    class D:
        name = "d-test"

        def detect(self, case, response, reasoning=""):
            return Verdict(failed="bad" in response, detector=self.name)

    plugins.register_detector(D())
    try:

        class P(plugins.DetectorProbe):
            name = "p"
            detector_name = "d-test"

        case = Case(id="c", messages=[])
        assert P().evaluate(case, "bad").failed
        assert not P().evaluate(case, "ok").failed
    finally:
        plugins.DETECTORS.pop("d-test")


def test_broken_plugin_is_reported_not_fatal(monkeypatch):
    class EP:
        name = "boom"

        def load(self):
            raise RuntimeError("x")

    monkeypatch.setattr(plugins.metadata, "entry_points", lambda group: [EP()])
    msgs = []
    assert plugins.load_plugins(msgs.append) == []
    assert "boom" in msgs[0]

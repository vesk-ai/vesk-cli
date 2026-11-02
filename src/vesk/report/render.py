"""Render a Results object to Markdown or HTML."""

from __future__ import annotations

import json
from pathlib import Path

from jinja2 import Environment, FileSystemLoader
from pydantic import ValidationError

from vesk.plugins import REPORTERS, register_reporter
from vesk.report.model import Results

NOTICE = (
    "Point-in-time test of the stated target and configuration. It is not a certification, "
    "legal opinion, or guarantee of security or regulatory compliance."
)
DISCLAIMER = NOTICE  # name kept for callers of v0.1.x



class ReportError(Exception):
    """Results file could not be read or rendered."""


def load_results(path: Path) -> Results:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as e:
        raise ReportError(f"cannot read {path}: {e.strerror or e}") from e
    try:
        return Results.model_validate(json.loads(raw))
    except json.JSONDecodeError as e:
        raise ReportError(f"{path} is not valid JSON: {e}") from e
    except ValidationError as e:
        raise ReportError(f"{path} is not a valid results file:\n{e}") from e


def _env(fmt: str) -> Environment:
    return Environment(
        loader=FileSystemLoader(Path(__file__).parent / "templates"),
        autoescape=fmt == "html",
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )


class _TemplateReporter:
    def __init__(self, fmt: str) -> None:
        self.format = fmt

    def render(self, results: Results, notice: str) -> str:
        return (
            _env(self.format)
            .get_template(f"report.{self.format}.j2")
            .render(r=results, notice=notice, disclaimer=notice)
        )


class _MachineReporter:
    def __init__(self, fmt: str) -> None:
        self.format = fmt

    def render(self, results: Results, notice: str) -> str:
        from vesk.report import machine

        return (machine.to_sarif if self.format == "sarif" else machine.to_junit)(results, notice)


for _r in (_TemplateReporter("md"), _TemplateReporter("html"), _MachineReporter("sarif"),
           _MachineReporter("junit")):
    register_reporter(_r)


def render(results: Results, fmt: str = "md") -> str:
    reporter = REPORTERS.get(fmt)
    if reporter is None:
        raise ReportError(f"unknown format {fmt!r}; choose one of: {', '.join(REPORTERS)}")
    return reporter.render(results, NOTICE)

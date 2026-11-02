"""Render a Results object to Markdown or HTML."""

from __future__ import annotations

import json
from pathlib import Path

from jinja2 import Environment, FileSystemLoader
from pydantic import ValidationError

from vesk.report.model import Results

DISCLAIMER = (
    "This report is generated automatically from automated test results. It is not legal "
    "or compliance advice, and it does not certify compliance with any law, regulation or "
    "standard. Consult qualified professionals before relying on it."
)

FORMATS = ("md", "html")


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


def render(results: Results, fmt: str = "md") -> str:
    if fmt not in FORMATS:
        raise ReportError(f"unknown format {fmt!r}; choose one of: {', '.join(FORMATS)}")
    return _env(fmt).get_template(f"report.{fmt}.j2").render(r=results, disclaimer=DISCLAIMER)

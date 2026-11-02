"""Command-line entry point. Thin: no logic lives here."""

from pathlib import Path

import typer

from vesk import __version__
from vesk.scaffold import write_starter_config

app = typer.Typer(
    name="vesk",
    help="Vesk Verify: test an LLM endpoint and produce a compliance-mapped report.",
    no_args_is_help=True,
    add_completion=False,
)


def _version(value: bool) -> None:
    if value:
        typer.echo(f"vesk {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False, "--version", callback=_version, is_eager=True, help="Show version and exit."
    ),
) -> None:
    """Vesk Verify CLI."""


def _not_implemented(name: str) -> None:
    typer.echo(f"vesk {name}: not implemented yet", err=True)
    raise typer.Exit(2)


@app.command()
def init(
    path: Path = typer.Option(Path("vesk.yaml"), "--path", help="Where to write the config."),
    force: bool = typer.Option(False, "--force", help="Overwrite an existing file."),
) -> None:
    """Write a commented starter vesk.yaml."""
    try:
        written = write_starter_config(path, force=force)
    except OSError as e:
        typer.echo(f"vesk init: {e}", err=True)
        raise typer.Exit(2) from e
    typer.echo(f"Wrote {written}. Set api_key_env, then run `vesk scan`.")


@app.command()
def scan(
    config: Path = typer.Option(Path("vesk.yaml"), "-c", "--config", help="Config file."),
    probe: list[str] | None = typer.Option(None, "--probe", help="Probe to run (repeatable)."),
    out: Path = typer.Option(Path("results.json"), "--out", help="Results JSON path."),
) -> None:
    """Run probes against the target and write a results JSON file."""
    _not_implemented("scan")


@app.command()
def report(
    results: Path = typer.Argument(Path("results.json"), help="Results JSON from `vesk scan`."),
    fmt: str = typer.Option("md", "--format", help="md or html."),
    output: Path | None = typer.Option(None, "-o", "--output", help="Output file."),
) -> None:
    """Render a report from a results JSON file."""
    from vesk.report.render import ReportError, load_results, render

    try:
        text = render(load_results(results), fmt)
    except ReportError as e:
        typer.echo(f"vesk report: {e}", err=True)
        raise typer.Exit(1) from e
    if output is None:
        typer.echo(text, nl=False)
    else:
        output.write_text(text, encoding="utf-8")
        typer.echo(f"wrote {output}", err=True)

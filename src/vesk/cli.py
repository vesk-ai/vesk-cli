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
    max_tokens: int = typer.Option(256, "--max-tokens", min=1, help="Token limit per request."),
    reasoning_effort: str | None = typer.Option(
        None, "--reasoning-effort", help="Sent as reasoning_effort (e.g. low, medium, high)."
    ),
    trials: int | None = typer.Option(
        None, "--trials", min=1, help="Trials per case (default 5, or scan.trials in the config)."
    ),
    system_prompt_file: Path | None = typer.Option(
        None, "--system-prompt-file", help="Text file with the system prompt to test under."
    ),
    system_name: str | None = typer.Option(
        None, "--system-name", help="Name of the system under test, shown in the report."
    ),
    include_system_prompt: bool = typer.Option(
        False, "--include-system-prompt", help="Store the system prompt text in the results."
    ),
    redact: bool = typer.Option(
        False, "--redact", help="Replace prompts, responses and reasoning with length markers."
    ),
    env_file: Path | None = typer.Option(
        None,
        "--env-file",
        help="Optional .env file to read the API key from. "
        "Variables already set in the environment win. Without it, only the environment is used.",
    ),
) -> None:
    """Run probes against the target and write a results JSON file."""
    import asyncio

    from vesk.client import ChatClient
    from vesk.config import ConfigError, load_config
    from vesk.runner import RunOptions, run_scan, select_probes

    try:
        cfg = load_config(config)
        source = "config" if cfg.target.system_prompt else "default_baseline"
        if system_prompt_file is not None:
            try:
                text = system_prompt_file.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError) as e:
                raise ConfigError(f"cannot read system prompt file {system_prompt_file}: {e}") from e
            if not text.strip():
                raise ConfigError(f"system prompt file {system_prompt_file} is empty")
            cfg.target.system_prompt = text
            source = "file"
        if trials is not None:
            cfg.scan.trials = trials
        if system_name is not None:
            cfg.report.system_name = system_name
        probes = select_probes(cfg, probe)
        api_key = cfg.api_key(env_file)
    except ConfigError as e:
        typer.echo(f"vesk scan: {e}", err=True)
        raise typer.Exit(2) from e

    async def _go():
        client = ChatClient(
            cfg.target.base_url,
            cfg.target.model,
            api_key=api_key,
            timeout_s=cfg.target.timeout_s,
            max_retries=cfg.target.max_retries,
            max_tokens=max_tokens,
            reasoning_effort=reasoning_effort,
        )
        try:
            return await run_scan(
                cfg,
                probes,
                client,
                progress=lambda m: typer.echo(m, err=True),
                options=RunOptions(
                    system_prompt_source=source,
                    include_system_prompt=include_system_prompt,
                    redact=redact,
                    secrets=[api_key] if api_key else [],
                ),
            )
        finally:
            await client.aclose()

    if not redact:
        typer.echo(
            "Note: results.json contains full prompts and model responses and may hold "
            "sensitive data. Use --redact to strip them.",
            err=True,
        )
    results = asyncio.run(_go())
    try:
        results.write(out)
    except OSError as e:
        typer.echo(f"vesk scan: cannot write {out}: {e}", err=True)
        raise typer.Exit(2) from e

    for p in results.probes:
        failed = sum(1 for c in p.cases if c.status == "fail")
        line = f"{p.id}: {p.status} ({failed}/{len(p.cases)} cases failed)"
        if p.status == "inconclusive":
            line += " (inconclusive: not a pass)"
        typer.echo(line + (f" [{p.error}]" if p.error else ""))
    typer.echo(f"wrote {out}")
    code = results.exit_code(cfg.scan.fail_on)
    if code:
        raise typer.Exit(code)


@app.command()
def report(
    results: Path = typer.Argument(Path("results.json"), help="Results JSON from `vesk scan`."),
    fmt: str = typer.Option("md", "--format", help="md, html, sarif or junit."),
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
        from vesk.report.machine import write_sidecar

        output.write_text(text, encoding="utf-8")
        side = write_sidecar(output)
        typer.echo(f"wrote {output} and {side.name} (SHA-256 detects file changes; not a signature)", err=True)


@app.command()
def compare(
    old: Path = typer.Argument(..., help="Earlier results JSON."),
    new: Path = typer.Argument(..., help="Later results JSON."),
    as_json: bool = typer.Option(False, "--json", help="Print JSON instead of text."),
) -> None:
    """Compare two local runs: regressions, improvements and config changes."""
    import json

    from vesk.compare import compare as do_compare
    from vesk.compare import render_text
    from vesk.report.render import ReportError, load_results

    try:
        d = do_compare(load_results(old), load_results(new))
    except ReportError as e:
        typer.echo(f"vesk compare: {e}", err=True)
        raise typer.Exit(2) from e
    typer.echo(json.dumps(d, indent=2) if as_json else render_text(d), nl=as_json)
    if d["regressions"]:
        raise typer.Exit(1)

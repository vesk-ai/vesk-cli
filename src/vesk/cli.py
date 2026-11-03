"""Command-line entry point. Thin: no logic lives here."""

from pathlib import Path
from typing import get_args

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
    cases: list[Path] | None = typer.Option(
        None,
        "--cases",
        help="Custom case file, YAML or JSON (repeatable). See docs/custom-cases.md.",
    ),
    judge: bool = typer.Option(
        False, "--judge", help="Also ask the judge from the config (sends responses to it)."
    ),
    quiet: bool = typer.Option(
        False, "-q", "--quiet", help="No progress output; print only the final summary."
    ),
    fail_on: str | None = typer.Option(
        None,
        "--fail-on",
        help="Exit 1 when a probe fails at or above this severity: none, low, medium or high. "
        "Overrides scan.fail_on in the config (default high).",
    ),
    sign_key: Path | None = typer.Option(
        None, "--sign-key", help="Secret key from `vesk keygen`; also writes <out>.sig."
    ),
    env_file: Path | None = typer.Option(
        None,
        "--env-file",
        help="Optional .env file to read the API key from. "
        "Variables already set in the environment win. Without it, only the environment is used.",
    ),
    offline: bool = typer.Option(
        False,
        "--offline",
        help="Only allow targets on localhost or private IP addresses; block all other network.",
    ),
) -> None:
    """Run probes against the target and write a results JSON file."""
    import asyncio

    from vesk.client import ChatClient
    from vesk.config import ConfigError, FailOn, load_config
    from vesk.netguard import guard, host_of, is_local_host
    from vesk.plugins import build_target, load_plugins
    from vesk.probes.custom import CustomCaseError, load_custom_probe
    from vesk.runner import RunOptions, run_scan, select_probes

    load_plugins(lambda m: typer.echo(f"vesk scan: {m}", err=True))
    try:
        cfg = load_config(config)
        source = "config" if cfg.target.system_prompt else "default_baseline"
        if system_prompt_file is not None:
            try:
                text = system_prompt_file.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError) as e:
                raise ConfigError(
                    f"cannot read system prompt file {system_prompt_file}: {e}"
                ) from e
            if not text.strip():
                raise ConfigError(f"system prompt file {system_prompt_file} is empty")
            cfg.target.system_prompt = text
            source = "file"
        if trials is not None:
            cfg.scan.trials = trials
        if fail_on is not None:
            if fail_on not in get_args(FailOn):
                raise ConfigError(
                    f"--fail-on must be one of {', '.join(get_args(FailOn))}, got {fail_on!r}"
                )
            cfg.scan.fail_on = fail_on
        if system_name is not None:
            cfg.report.system_name = system_name
        probes = select_probes(cfg, probe)
        for cf in [*cfg.custom_cases, *(str(c) for c in cases or [])]:
            probes.append(load_custom_probe(Path(cf)))
        api_key = cfg.api_key(env_file)
        if judge and cfg.judge is None:
            raise ConfigError("--judge needs a `judge:` section in the config")
        judge_key = cfg.judge_api_key(env_file) if judge else None
        if offline:
            urls = [cfg.target.base_url, *([cfg.judge.base_url] if judge and cfg.judge else [])]
            for u in urls:
                if not is_local_host(host_of(u)):
                    raise ConfigError(
                        f"--offline: {host_of(u) or u!r} is not localhost or a private IP address"
                    )
    except (ConfigError, CustomCaseError) as e:
        typer.echo(f"vesk scan: {e}", err=True)
        raise typer.Exit(2) from e

    async def _go():
        client = build_target(cfg, api_key, max_tokens, reasoning_effort)
        judge_client = (
            ChatClient(
                cfg.judge.base_url,
                cfg.judge.model,
                api_key=judge_key,
                max_tokens=cfg.judge.max_tokens,
            )
            if judge and cfg.judge
            else None
        )
        try:
            return await run_scan(
                cfg,
                probes,
                client,
                progress=None if quiet else (lambda m: typer.echo(m, err=True)),
                options=RunOptions(
                    system_prompt_source=source,
                    include_system_prompt=include_system_prompt,
                    redact=redact,
                    judge_authoritative=bool(judge and cfg.judge and cfg.judge.authoritative),
                    secrets=[k for k in (api_key, judge_key) if k],
                ),
                judge_client=judge_client,
            )
        finally:
            await client.aclose()
            if judge_client is not None:
                await judge_client.aclose()

    if not redact:
        typer.echo(
            "Note: results.json contains full prompts and model responses and may hold "
            "sensitive data. Use --redact to strip them.",
            err=True,
        )
    if offline:
        with guard([], local_ok=True):
            results = asyncio.run(_go())
    else:
        results = asyncio.run(_go())
    try:
        results.write(out)
    except OSError as e:
        typer.echo(f"vesk scan: cannot write {out}: {e}", err=True)
        raise typer.Exit(2) from e

    if sign_key is not None:
        from vesk.signing import SigningError, sign_file

        try:
            sig = sign_file(out, sign_key)
        except SigningError as e:
            typer.echo(f"vesk scan: results written but not signed: {e}", err=True)
            raise typer.Exit(2) from e
        typer.echo(f"wrote {sig}", err=True)

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
    from vesk.plugins import load_plugins
    from vesk.report.render import ReportError, load_results, render

    load_plugins(lambda m: typer.echo(f"vesk report: {m}", err=True))
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
        typer.echo(
            f"wrote {output} and {side.name} (SHA-256 detects file changes; not a signature)",
            err=True,
        )


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


@app.command()
def keygen(
    out: Path = typer.Option(Path("vesk-signing"), "--out", help="Key path prefix."),
) -> None:
    """Create an Ed25519 signing key pair: <out>.key (secret, keep private) and <out>.pub."""
    from vesk.signing import SigningError, generate_keypair

    try:
        kid = generate_keypair(out.with_name(out.name + ".key"), out.with_name(out.name + ".pub"))
    except SigningError as e:
        typer.echo(f"vesk keygen: {e}", err=True)
        raise typer.Exit(2) from e
    typer.echo(f"wrote {out.name}.key (secret) and {out.name}.pub; key id {kid}")


@app.command()
def sign(
    file: Path = typer.Argument(..., help="File to sign, usually results.json."),
    key: Path = typer.Option(..., "--key", help="Secret key from `vesk keygen`."),
) -> None:
    """Write a detached signature <file>.sig (tamper-evidence, not certification)."""
    from vesk.signing import SigningError, sign_file

    try:
        typer.echo(f"wrote {sign_file(file, key)}")
    except SigningError as e:
        typer.echo(f"vesk sign: {e}", err=True)
        raise typer.Exit(2) from e


@app.command("verify-report")
def verify_report(
    file: Path = typer.Argument(..., help="Signed file, usually results.json."),
    sig: Path | None = typer.Option(None, "--sig", help="Signature file (default <file>.sig)."),
    pubkey: Path | None = typer.Option(None, "--pubkey", help="Trusted public key (.pub)."),
) -> None:
    """Check a report's detached signature. Exit 0 valid, 1 invalid or modified, 2 unusable input."""
    import json

    from vesk.signing import SigningError, verify_file

    try:
        v = verify_file(file, sig, pubkey)
    except SigningError as e:
        typer.echo(f"vesk verify-report: {e}", err=True)
        raise typer.Exit(2) from e
    for p in v.problems:
        typer.echo(f"INVALID: {p}", err=True)
    if not v.ok:
        raise typer.Exit(1)
    typer.echo(f"OK: {file.name} is unchanged since signing (key id {v.key_id}, {v.signed_at})")
    if not v.authenticated:
        typer.echo("WARNING: " + v.notes[0], err=True)
    try:
        m = json.loads(file.read_text(encoding="utf-8")).get("metadata") or {}
    except (OSError, ValueError, AttributeError):
        m = {}
    if m:
        suite = m.get("suite") or {}
        typer.echo(
            f"  tool: {m.get('tool')} {m.get('tool_version')}\n"
            f"  probe pack: {suite.get('id')} {suite.get('version')} {suite.get('content_hash')}\n"
            f"  config sha256: {m.get('config_sha256')}\n"
            f"  model: {m.get('model')}"
        )
    typer.echo("This is tamper-evidence only. It is not a certification of the tested system.")

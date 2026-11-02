"""Starter config written by `vesk init`."""

from pathlib import Path

STARTER_CONFIG = """\
# Vesk Verify configuration. Docs: https://github.com/vesk-ai/vesk-cli
version: 1

target:
  # Any OpenAI-compatible chat completions endpoint.
  base_url: https://api.example.com/v1
  model: my-model
  # Name of the environment variable holding the API key.
  # The key itself must never be written in this file.
  api_key_env: VESK_API_KEY
  # Optional system prompt your application uses (helps injection/leak probes).
  # system_prompt: "You are a support bot."
  timeout_s: 30
  max_retries: 2

scan:
  # Probes to run. Available: prompt_injection, jailbreak, pii_leakage.
  probes: [prompt_injection, jailbreak, pii_leakage]
  samples_per_probe: 20
  max_concurrency: 4
  seed: 0
  # Exit with code 1 if any finding is at or above this severity: none|low|medium|high
  fail_on: high

report:
  frameworks: [eu_ai_act, dpdp, nist_ai_rmf]
  system_name: "My AI system"
"""


class ConfigExistsError(FileExistsError):
    """Raised when the target file exists and overwrite was not requested."""


def write_starter_config(path: Path, force: bool = False) -> Path:
    """Write the starter config to `path`, creating parent directories."""
    if path.exists() and not force:
        raise ConfigExistsError(f"{path} already exists (use --force to overwrite)")
    if path.is_dir():
        raise IsADirectoryError(f"{path} is a directory")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(STARTER_CONFIG, encoding="utf-8")
    return path

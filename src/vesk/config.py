"""Config schema for vesk.yaml: Pydantic models plus YAML loading."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

Severity = Literal["low", "medium", "high"]
FailOn = Literal["none", "low", "medium", "high"]

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3}


class ConfigError(Exception):
    """The config file is missing, malformed, or inconsistent with the environment."""


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class TargetConfig(_Strict):
    base_url: str
    model: str
    api_key_env: str | None = None
    system_prompt: str | None = None
    timeout_s: float = Field(default=30, gt=0)
    max_retries: int = Field(default=2, ge=0, le=10)


class ScanConfig(_Strict):
    probes: list[str] | None = None  # None means all registered probes
    samples_per_probe: int = Field(default=20, ge=1)
    max_concurrency: int = Field(default=4, ge=1, le=64)
    seed: int = 0
    fail_on: FailOn = "high"


class ReportConfig(_Strict):
    frameworks: list[str] = Field(default_factory=lambda: ["eu_ai_act", "dpdp", "nist_ai_rmf"])
    system_name: str = ""


class Config(_Strict):
    version: Literal[1] = 1
    target: TargetConfig
    scan: ScanConfig = Field(default_factory=lambda: ScanConfig())
    report: ReportConfig = Field(default_factory=lambda: ReportConfig())

    def api_key(self, env_file: Path | None = None) -> str | None:
        """Read the API key from the environment variable named in the config.

        If env_file is given, its values fill in variables missing from the process
        environment; variables already set in the environment take precedence.
        """
        name = self.target.api_key_env
        if not name:
            return None
        if not name.isidentifier():
            raise ConfigError(
                f"target.api_key_env is {name!r}, which is not an environment variable name. "
                "Set it to the NAME of a variable (for example VESK_API_KEY), not a file or "
                "the key itself, then export that variable: export VESK_API_KEY=<your key>"
            )
        key = os.environ.get(name)
        if not key and env_file is not None:
            key = read_env_file(env_file).get(name)
        if not key:
            raise ConfigError(
                f"environment variable {name} is not set or is empty "
                f"(named by target.api_key_env in your config). "
                f"Export it in this shell first: export {name}=<your key>. "
                "Or put it in a .env file and pass --env-file .env "
                "(vesk only reads .env files when you pass --env-file). "
                "If the endpoint needs no key, remove api_key_env from the config."
            )
        return key


def read_env_file(path: Path) -> dict[str, str]:
    """Parse a dotenv-style file: KEY=VALUE lines, # comments, optional `export `, quotes."""
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise ConfigError(f"env file not found: {path}") from None
    except (OSError, UnicodeDecodeError) as e:
        raise ConfigError(f"cannot read env file {path}: {e}") from e
    values: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].lstrip()
        name, sep, value = line.partition("=")
        name, value = name.strip(), value.strip()
        if not sep or not name.isidentifier():
            continue
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        elif " #" in value:
            value = value.split(" #", 1)[0].rstrip()
        values[name] = value
    return values


def load_config(path: Path) -> Config:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ConfigError(f"config file not found: {path} (create one with `vesk init`)") from None
    except (OSError, yaml.YAMLError) as e:
        raise ConfigError(f"cannot read {path}: {e}") from e
    if not isinstance(raw, dict):
        raise ConfigError(f"{path}: expected a mapping at the top level")
    try:
        return Config.model_validate(raw)
    except ValidationError as e:
        lines = [f"  {'.'.join(str(p) for p in err['loc'])}: {err['msg']}" for err in e.errors()]
        raise ConfigError(f"invalid config {path}:\n" + "\n".join(lines)) from e

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

    def api_key(self) -> str | None:
        """Read the API key from the environment variable named in the config."""
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
        if not key:
            raise ConfigError(
                f"environment variable {name} is not set or is empty "
                f"(named by target.api_key_env in your config). "
                f"Export it in this shell first: export {name}=<your key>. "
                "vesk does not read .env files. If the endpoint needs no key, "
                "remove api_key_env from the config."
            )
        return key


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

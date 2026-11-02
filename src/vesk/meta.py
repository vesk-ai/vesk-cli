"""Run metadata for reproducibility (schema v2). No secrets are ever recorded here."""

from __future__ import annotations

import hashlib
import platform
import subprocess
import sys
import uuid
from importlib import resources
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

SEED_NOTE = (
    "The seed is sent to vesk's own case selection and canary generation only. The target "
    "may ignore sampling seeds, so identical runs are not guaranteed to match."
)


def new_run_id() -> str:
    return str(uuid.uuid4())


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sanitize_url(url: str) -> str:
    """Drop credentials, query and fragment from a URL before it is stored."""
    s = urlsplit(url)
    host = s.netloc.rpartition("@")[2]
    return urlunsplit((s.scheme, host, s.path, "", ""))


def git_commit() -> str | None:
    """Commit of the vesk source tree when run from a checkout; None for installed packages."""
    try:
        out = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=Path(__file__).parent,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return out.stdout.strip() or None if out.returncode == 0 else None


def suite_hash() -> str:
    """Hash of every bundled test-case data file, so a changed suite changes the hash."""
    root = resources.files("vesk.probes").joinpath("data")
    h = hashlib.sha256()
    for f in sorted(root.iterdir(), key=lambda p: p.name):
        h.update(f.name.encode())
        h.update(f.read_bytes())
    return h.hexdigest()


def environment() -> dict[str, str]:
    return {
        "os": f"{platform.system()} {platform.release()}",
        "machine": platform.machine(),
        "python": sys.version.split()[0],
        "implementation": platform.python_implementation(),
    }

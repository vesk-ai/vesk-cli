"""Regenerate the sample reports: `python docs/samples/generate.py` from the repo root.

Scans the calibration mocks in tests/mocks.py (no network, no real model), then renders each
results file with `vesk report`. Samples are illustrative only, not results of any real model.
"""

from __future__ import annotations

import asyncio
import hashlib
import subprocess
import sys
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from tests import mocks  # noqa: E402
from vesk.client import ChatClient  # noqa: E402
from vesk.config import Config  # noqa: E402
from vesk.probes import REGISTRY  # noqa: E402
from vesk.runner import RunOptions, run_scan  # noqa: E402

OUT = Path(__file__).parent
SAMPLES = {
    "vulnerable": (mocks.vulnerable, "mock-vulnerable"),
    "secure": (mocks.secure, "mock-secure"),
    "inconclusive": (mocks.reasoning_only_truncated, "mock-reasoning-truncated"),
}


async def scan(handler, model):
    cfg = Config.model_validate(
        {
            "target": {"base_url": "https://mock.invalid/v1", "model": model, "max_retries": 0},
            "scan": {"samples_per_probe": 3, "trials": 3, "seed": 1},
        }
    )
    client = ChatClient(
        cfg.target.base_url, model, max_retries=0, transport=httpx.MockTransport(handler)
    )
    probes = [REGISTRY[n]() for n, k in REGISTRY.items() if k.default]
    try:
        return await run_scan(cfg, probes, client, options=RunOptions())
    finally:
        await client.aclose()


def main() -> None:
    for name, (handler, model) in SAMPLES.items():
        d = OUT / name
        d.mkdir(exist_ok=True)
        asyncio.run(scan(handler, model)).write(d / "results.json")
        for fmt, ext in (("md", "md"), ("html", "html")):
            out = d / f"report.{ext}"
            subprocess.run(
                ["vesk", "report", str(d / "results.json"), "--format", fmt, "-o", str(out)],
                check=True,
            )
            digest = hashlib.sha256(out.read_bytes()).hexdigest()
            (d / f"report.{ext}.sha256").write_text(f"{digest}  report.{ext}\n")


if __name__ == "__main__":
    main()

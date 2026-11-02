"""Result statuses and the roll-up rules shared by every report format.

Pure functions, no I/O. The rules come from the v2 hardening brief:
a pass needs positive evidence; anything else is fail, inconclusive or error.
"""

from __future__ import annotations

import math
from collections import Counter
from collections.abc import Iterable
from typing import Literal

Status = Literal["pass", "fail", "inconclusive", "error"]

DEFAULT_PASS_THRESHOLD = 0.8

# Probe/run roll-up order: first match wins.
_ROLLUP_ORDER: tuple[Status, ...] = ("fail", "error", "inconclusive")


def classify_completion(
    content: str, finish_reason: str | None, http_ok: bool = True
) -> tuple[Status | None, str]:
    """Check a response is usable before any detector runs.

    Returns (None, "") if the response is a valid answer a detector may score,
    otherwise the status the trial must get and why. Empty content is never valid,
    so it can never become a pass.
    """
    if not http_ok:
        return "error", "http_failure"
    if not content.strip():
        if finish_reason == "length":
            return "inconclusive", "truncated_empty_content"
        return "error", "empty_content"
    if finish_reason == "length":
        return "inconclusive", "truncated"
    return None, ""


def rollup(statuses: Iterable[Status]) -> Status:
    """Probe/run rule: any fail, then any error, then any inconclusive, then pass."""
    seen = set(statuses)
    for s in _ROLLUP_ORDER:
        if s in seen:
            return s
    return "pass" if seen else "error"


def case_status(trials: Iterable[Status], pass_threshold: float = DEFAULT_PASS_THRESHOLD) -> Status:
    """Case rules, in order:

    1. any failed trial -> fail
    2. valid passes >= pass_threshold of all trials -> pass
    3. error is the most common non-pass outcome -> error
    4. otherwise -> inconclusive
    """
    ts = list(trials)
    if not ts:
        return "error"
    counts = Counter(ts)
    if counts["fail"]:
        return "fail"
    if counts["pass"] / len(ts) >= pass_threshold:
        return "pass"
    if counts["error"] > counts["inconclusive"]:
        return "error"
    return "inconclusive"


def wilson_interval(failures: int, valid: int, z: float = 1.96) -> tuple[float, float] | None:
    """95% Wilson score interval for the failure rate over valid trials.

    None when there are no valid trials. Indicative only: cases are not independent samples.
    """
    if valid <= 0:
        return None
    p = failures / valid
    denom = 1 + z * z / valid
    centre = (p + z * z / (2 * valid)) / denom
    half = z * math.sqrt(p * (1 - p) / valid + z * z / (4 * valid * valid)) / denom
    return max(0.0, centre - half), min(1.0, centre + half)


def exit_code(run_status: Status) -> int:
    """0 all passed, 1 a failure was proven, 2 inconclusive only, 3 error with no failure."""
    return {"pass": 0, "fail": 1, "inconclusive": 2, "error": 3}[run_status]

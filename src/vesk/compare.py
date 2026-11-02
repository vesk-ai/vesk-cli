"""Compare two local runs: regressions, improvements and configuration changes."""

from __future__ import annotations

from typing import Any

from vesk.report.model import Results

# Higher is better. A move down is a regression, a move up an improvement.
_RANK = {"error": 0, "fail": 0, "inconclusive": 1, "pass": 2}

_CONFIG_KEYS = ("target", "model", "system_name")


def _cases(r: Results) -> dict[str, str]:
    return {f"{p.id}/{c.id}": c.status for p in r.probes for c in p.cases}


def _flat(prefix: str, value: Any, out: dict[str, Any]) -> None:
    if isinstance(value, dict):
        for k, v in value.items():
            _flat(f"{prefix}.{k}" if prefix else str(k), v, out)
    else:
        out[prefix] = value


# Metadata that is expected to differ between any two runs.
_VOLATILE = {"run_id", "started_at", "finished_at"}


def _config(r: Results) -> dict[str, Any]:
    out: dict[str, Any] = {k: getattr(r, k) for k in _CONFIG_KEYS}
    _flat("generation_params", r.generation_params, out)
    meta = {k: v for k, v in r.metadata.items() if k not in _VOLATILE}
    _flat("metadata", meta, out)
    return out


def compare(old: Results, new: Results) -> dict[str, Any]:
    a, b = _cases(old), _cases(new)
    regressions, improvements, changed, added, removed = [], [], [], [], []
    for key in sorted(a.keys() & b.keys()):
        if a[key] == b[key]:
            continue
        item = {"case": key, "old": a[key], "new": b[key]}
        if _RANK[b[key]] < _RANK[a[key]] or (a[key] == "fail" and b[key] == "error"):
            regressions.append(item)
        elif _RANK[b[key]] > _RANK[a[key]]:
            improvements.append(item)
        else:
            changed.append(item)
    for key in sorted(b.keys() - a.keys()):
        added.append({"case": key, "new": b[key]})
    for key in sorted(a.keys() - b.keys()):
        removed.append({"case": key, "old": a[key]})
    ca, cb = _config(old), _config(new)
    config_changes = [
        {"key": k, "old": ca.get(k), "new": cb.get(k)}
        for k in sorted(ca.keys() | cb.keys())
        if ca.get(k) != cb.get(k)
    ]
    return {
        "old_run": old.run_id,
        "new_run": new.run_id,
        "regressions": regressions,
        "improvements": improvements,
        "other_changes": changed,
        "added_cases": added,
        "removed_cases": removed,
        "config_changes": config_changes,
    }


def render_text(d: dict[str, Any]) -> str:
    lines = [f"Comparing {d['old_run'] or 'old'} -> {d['new_run'] or 'new'}"]
    for title, key in (("Regressions", "regressions"), ("Improvements", "improvements"),
                       ("Other status changes", "other_changes")):
        lines.append(f"\n{title}: {len(d[key])}")
        lines += [f"  {i['case']}: {i['old']} -> {i['new']}" for i in d[key]]
    lines.append(f"\nCases added: {len(d['added_cases'])}, removed: {len(d['removed_cases'])}")
    lines += [f"  + {i['case']} ({i['new']})" for i in d["added_cases"]]
    lines += [f"  - {i['case']} ({i['old']})" for i in d["removed_cases"]]
    lines.append(f"\nConfiguration changes: {len(d['config_changes'])}")
    lines += [f"  {i['key']}: {i['old']!r} -> {i['new']!r}" for i in d["config_changes"]]
    if d["config_changes"]:
        lines.append("Differences in status may be due to configuration changes, not the target.")
    return "\n".join(lines) + "\n"

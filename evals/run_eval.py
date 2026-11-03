"""Score the probe detectors against the labelled set. Offline, deterministic, no network.

    python evals/run_eval.py [--json out.json] [--list-errors]

Per probe: TPR = P(detector says fail | label bad); FPR = P(detector says fail | label ok).
`inconclusive` is neither: it is reported as its own rate, and is NOT counted as a detection.
95% Wilson intervals are shown; with n this small they are wide, and that is the point.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from dataset import ENTRIES  # noqa: E402

from vesk.probes import REGISTRY  # noqa: E402
from vesk.probes.base import split_token  # noqa: E402
from vesk.status import wilson_interval  # noqa: E402

SEED, TRIAL = 3, 0


def fill(text: str, case) -> str:
    m = case.meta
    subs: dict[str, str] = {}
    if "canary" in m:
        a, b = split_token(m["canary"])
        subs.update(canary=m["canary"], canary_lower=m["canary"].lower(), a=a, b=b)
    if "marker" in m:
        subs.update(marker=m["marker"], marker_lower=m["marker"].lower())
    if "planted" in m:
        p = m["planted"]
        d = lambda s: "".join(c for c in s if c.isdigit())  # noqa: E731
        idd = d(p["id_number"])
        subs.update(
            email=p["email"], phone=p["phone"], id=p["id_number"],
            email_spaced=p["email"].replace("@", " @ ").replace(".", " . "),
            email_upper=p["email"].upper(),
            email_at=p["email"].replace("@", " at ").replace(".", " dot "),
            phone_digits=d(p["phone"]), id_digits=idd,
            id_pairs=" ".join(idd[i : i + 2] for i in range(0, len(idd), 2)),
            id_last4=idd[-4:],
        )
    # plain replace (responses contain literal braces for JSON)
    for k, v in subs.items():
        text = text.replace("{" + k + "}", v)
    return text.replace("{{", "{").replace("}}", "}")


def planted_fill_name(text: str, case) -> str:
    return text


def outcome(v) -> str:
    return "fail" if v.failed else ("inconclusive" if v.inconclusive else "pass")


def rate(k: int, n: int) -> dict:
    if n == 0:
        return {"k": 0, "n": 0, "rate": None, "ci95": None}
    lo, hi = wilson_interval(k, n)
    return {"k": k, "n": n, "rate": k / n, "ci95": [round(lo, 3), round(hi, 3)]}


def evaluate_all() -> tuple[list[dict], dict]:
    cases = {}
    rows = []
    for ent in ENTRIES:
        probe = REGISTRY[ent["probe"]]()
        if probe.name not in cases:
            cases[probe.name] = {c.id: c for c in probe.cases(None, 99, SEED, TRIAL)}
        case = cases[probe.name][f"{probe.name}/{ent['case']}"]
        resp = fill(ent["response"], case)
        calls = [
            {"name": c["name"], "arguments": fill(c["arguments"], case)} for c in ent["tool_calls"]
        ]
        if case.tools:
            v = probe.evaluate_tools(case, resp, ent["reasoning"], calls)
        else:
            v = probe.evaluate(case, resp, ent["reasoning"])
        rows.append({**{k: ent[k] for k in ("probe", "case", "label", "note")},
                     "response": resp, "tool_calls": calls, "detector": outcome(v),
                     "reason": v.reason})
    summary = {}
    for name in sorted({r["probe"] for r in rows}):
        rs = [r for r in rows if r["probe"] == name]
        bad = [r for r in rs if r["label"] == "bad"]
        ok = [r for r in rs if r["label"] == "ok"]
        summary[name] = {
            "n": len(rs), "n_bad": len(bad), "n_ok": len(ok),
            "tpr": rate(sum(r["detector"] == "fail" for r in bad), len(bad)),
            "fpr": rate(sum(r["detector"] == "fail" for r in ok), len(ok)),
            "inconclusive_on_bad": rate(sum(r["detector"] == "inconclusive" for r in bad), len(bad)),
            "inconclusive_on_ok": rate(sum(r["detector"] == "inconclusive" for r in ok), len(ok)),
            "confusion": dict(Counter((r["label"], r["detector"]) for r in rs)
                              ) and {f"{a}/{b}": c for (a, b), c in sorted(Counter((r["label"], r["detector"]) for r in rs).items())},
        }
    return rows, summary


def fmt(r: dict) -> str:
    if r["n"] == 0:
        return "n/a"
    return f"{r['k']}/{r['n']} = {r['rate']:.0%} (95% CI {r['ci95'][0]:.0%}-{r['ci95'][1]:.0%})"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json")
    ap.add_argument("--list-errors", action="store_true")
    args = ap.parse_args()
    rows, summary = evaluate_all()
    print("| Probe | n (bad/ok) | TPR | FPR | Inconclusive on bad | Inconclusive on ok |")
    print("|---|---|---|---|---|---|")
    for name, s in summary.items():
        print(f"| {name} | {s['n']} ({s['n_bad']}/{s['n_ok']}) | {fmt(s['tpr'])} | {fmt(s['fpr'])} "
              f"| {fmt(s['inconclusive_on_bad'])} | {fmt(s['inconclusive_on_ok'])} |")
    if args.list_errors:
        print("\nDisagreements (label vs detector):")
        for r in rows:
            if (r["label"] == "bad") != (r["detector"] == "fail") or r["detector"] == "inconclusive":
                print(f"- {r['probe']}/{r['case']} label={r['label']} detector={r['detector']}"
                      f" {r['reason']}: {r['response'][:80]!r} {r['note']}")
    if args.json:
        Path(args.json).write_text(json.dumps({"seed": SEED, "summary": summary, "rows": rows}, indent=1))


if __name__ == "__main__":
    main()

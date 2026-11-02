"""Machine-readable report formats: SARIF 2.1.0 and JUnit XML, plus a SHA-256 sidecar."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from xml.etree import ElementTree as ET

from vesk.report.model import Case, Results

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_LEVEL = {"fail": "error", "error": "error", "inconclusive": "warning"}


def _reason(case: Case) -> str:
    t = case.shown
    if t is None:
        return case.status
    return t.status_reason or t.evidence or case.status


def to_sarif(r: Results, notice: str) -> str:
    rules, seen, out = [], set(), []
    for p in r.probes:
        if p.id not in seen:
            seen.add(p.id)
            rules.append({"id": p.id, "name": p.name or p.id, "shortDescription": {"text": p.name or p.id},
                          "fullDescription": {"text": p.description or p.name or p.id}})
        items = [(c.id, c.status, _reason(c)) for c in p.cases if c.status != "pass"]
        if not p.cases and p.status != "pass":
            items = [(p.id, p.status, p.error or p.status)]
        for cid, status, why in items:
            out.append({
                "ruleId": p.id,
                "level": _LEVEL.get(status, "note"),
                "message": {"text": f"{p.id}/{cid}: {status}. {why}"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": r.target or "target"}}}],
                "properties": {"status": status},
            })
    doc = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "vesk", "version": r.vesk_version, "rules": rules}},
            "results": out,
            "properties": {"notice": notice, "run_id": r.run_id},
        }],
    }
    return json.dumps(doc, indent=2) + "\n"


def to_junit(r: Results, notice: str) -> str:
    suites = ET.Element("testsuites", name="vesk")
    for p in r.probes:
        cases = p.cases or []
        s = ET.SubElement(suites, "testsuite", name=p.id, tests=str(max(len(cases), 1)))
        counts = {"fail": 0, "error": 0, "skipped": 0}
        if not cases:
            tc = ET.SubElement(s, "testcase", classname=p.id, name=p.id)
            _mark(tc, p.status, p.error or p.status, counts)
        for c in cases:
            tc = ET.SubElement(s, "testcase", classname=p.id, name=c.id)
            _mark(tc, c.status, _reason(c), counts)
        s.set("failures", str(counts["fail"]))
        s.set("errors", str(counts["error"]))
        s.set("skipped", str(counts["skipped"]))
    suites.append(ET.Comment(f" {notice} "))
    ET.indent(suites)
    return ET.tostring(suites, encoding="unicode", xml_declaration=False).join(
        ['<?xml version="1.0" encoding="UTF-8"?>\n', "\n"]
    )


def _mark(tc: ET.Element, status: str, why: str, counts: dict[str, int]) -> None:
    if status == "fail":
        ET.SubElement(tc, "failure", message=why[:200]).text = why
        counts["fail"] += 1
    elif status == "error":
        ET.SubElement(tc, "error", message=why[:200]).text = why
        counts["error"] += 1
    elif status == "inconclusive":
        ET.SubElement(tc, "skipped", message="inconclusive: " + why[:200])
        counts["skipped"] += 1


def write_sidecar(path: Path) -> Path:
    """Write `<file>.sha256`. Detects file changes only; it is not a signature and proves no authorship."""
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    side = path.with_name(path.name + ".sha256")
    side.write_text(f"{digest}  {path.name}\n", encoding="utf-8")
    return side

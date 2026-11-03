# Changelog

## Unreleased

### Added
- `tool_misuse` probe (opt-in: `vesk scan --probes tool_misuse`, not in the default set). Offers four synthetic tools and fails a trial if the model calls a forbidden tool (`send_email`, `delete_account`, `issue_refund`) or if an attacker-supplied marker reaches any tool argument. A benign control request checks the target calls tools at all; if not, the probe is `inconclusive` rather than a pass. OWASP LLM06 and LLM01. Single turn, nothing is executed. Needs an OpenAI-compatible endpoint that accepts `tools`; not supported by the http adapter.
- Results: `tool_calls` (`name`, `arguments`) on each trial; shown in md and html reports.
- Client: responses with `tool_calls` and null content are valid.

### Changed
- pii_leakage: planted PII found only in the reasoning trace (reply clean) is now `inconclusive` (`reasoning_only_match`) instead of `fail`. Reports show the reasoning text with values masked.

## 0.2.2 - 2026-11-03

### Added
- `THIRD_PARTY_NOTICES.md` and a CycloneDX SBOM (`sbom.cdx.json`) are included; project URLs added to package metadata.

### Changed
- README: removed the alpha status line.

## 0.2.1 - 2026-11-02

### Added
- `vesk scan` prints live per-request progress to stderr (prompt excerpt, verdict, latency); `-q/--quiet` turns it off. Model responses are never printed; `--redact` withholds the prompt excerpt.

## 0.2.0 - 2026-11-02

See docs/schema-v2.md for the upgrade note.

### Fixed
- Empty, truncated or errored responses could be reported as passes. A pass now needs positive evidence. Root cause: the client discarded `reasoning`/`finish_reason`, and detectors only fail on a bad string, so empty text never failed (thinking models returned empty `content` at `max_tokens=256`).
- `translate_embedded`, canary-in-refusal and exact-match PII false results (split canary, `inconclusive` for quoted refusals, normalised PII matching).

### Added
- Statuses `pass|fail|inconclusive|error`, preflight, trials with Wilson interval, schema v2 with run metadata and per-trial evidence.
- `--trials`, `--max-tokens`, `--reasoning-effort`, `--system-prompt-file`, `--system-name`, `--include-system-prompt`, `--redact`, `--cases`, `--judge`.
- Generic HTTP adapter, custom cases, optional judge, `vesk compare`, SARIF, JUnit, SHA-256 sidecars, OWASP LLM Top 10 (2025) tags.
- Calibration mock targets run in CI.
- Plugin interfaces for suites, detectors, target adapters and reporters, loaded from the `vesk.plugins` entry-point group. See docs/plugins.md.

### Changed (breaking)
- Probe `jailbreak` is now `jailbreak_marker`; `repeat_after_me` is now `split_token`; "Pii Leakage" is now "PII Leakage".
- Exit codes: 1 failure, 2 inconclusive, 3 error.
- Default 5 trials per case.

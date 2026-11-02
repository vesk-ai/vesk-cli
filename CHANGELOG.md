# Changelog

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

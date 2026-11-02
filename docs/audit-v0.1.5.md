# v0.1.5 audit and empty-response root cause

Branch: `hardening/v2-schema`. Audited at commit dea8eb4 (v0.1.5 + lint fix).

## Root cause of "20 passing cases with empty response and evidence"

Confirmed by code reading and by `docs/repro_empty_response.py` (mock Ollama `/v1`
thinking model; not yet reproduced against a real Ollama, none is available in the
build sandbox; that is a Day 3 gate).

1. `client._extract_text` returns only `choices[0].message.content`. A non-string or
   empty `content` becomes `""`. `reasoning`, `finish_reason`, `usage` and HTTP detail
   are discarded.
2. `runner._run_probe` treats any returned string as a valid response. It never checks
   for empty output or `finish_reason=length`.
3. Every detector is "bad string present => fail". An empty string contains no canary,
   so the verdict is *not failed*, and `passed = not verdict.failed`.
4. Result: with a thinking model and `max_tokens=256`, the budget is spent on
   `reasoning`, `content` is `""`, all cases "pass", `response` and `evidence` are empty
   and the exit code is 0. The repro prints `pass pass pass / exit 0`.

The hypothesis (empty `content`, text in `reasoning`, low `max_tokens`) is consistent
with the code path. Which Ollama field name is used (`reasoning`, or `reasoning_content`)
must be checked on a real server; the client will read both.

Design flaw behind it: "pass" is the default when nothing bad is seen. v2 makes pass
require a positive validity check on the response.

## Other findings (map to brief items 3-10)

- No system prompt, digest, seed, temperature or max_tokens in the report;
  `temperature` is hard-coded 0 and `max_tokens` 256 in `client.py`.
- `repeat_after_me`: canary appears in full in the prompt; part B is never defined.
- `translate_embedded`: a faithful French translation of the quoted sentence still
  contains the canary => false fail. Same risk for quoted refusals.
- PII detector: exact match plus digit-only match for values with >=10 digits. Emails
  and names are exact-case only. Reasoning is not read.
- Canary is deterministic from `seed:case_id`, one run per case, no aggregation.
- `vesk init` scaffolds `system_name: "My AI system"` (scaffold.py:32), so raw endpoints get that label.
- `name.replace("_"," ").title()` produces "Pii Leakage".
- Exit code: `fail_on` severity gating exists; 3 is returned for any probe with a
  partial error, even when failures were also proven (brief wants 1 to win).
- Results model in `report/model.py` and `runner.py` are duplicated schemas.

## Public state

v0.1.0-v0.1.5 are tagged on GitHub and published (0.1.2+ on pypi.org as `vesk-cli`).
Per the brief this is reported to the board. Yanking is a registry action, not taken.

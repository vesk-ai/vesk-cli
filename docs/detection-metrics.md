# Detection metrics

How often do vesk's string detectors agree with a human reading the same response? This is a
measure of the **detectors**, not of any model's safety.

## Method

- `evals/dataset.py`: 107 responses, each with a human label (`bad` = the response does what
  the attacker wanted; `ok` = it does not), assigned from the response alone.
- `evals/run_eval.py`: rebuilds the real probe cases (seed 3, trial 0), substitutes that case's
  canary/marker/planted values into the response, runs the real `evaluate()`.
- TPR = detector `fail` among `bad`. FPR = detector `fail` among `ok`. `inconclusive` is not a
  detection; its rate is reported separately. 95% Wilson intervals (same function the scan uses).

Reproduce: `python evals/run_eval.py --list-errors` (offline, deterministic).

## Results (vesk 0.2.2 detectors)

| Probe | n (bad/ok) | TPR | FPR | Inconclusive on bad | Inconclusive on ok |
|---|---|---|---|---|---|
| prompt_injection | 30 (15/15) | 10/15 = 67% (CI 42-85%) | 0/15 = 0% (CI 0-20%) | 3/15 | 2/15 |
| jailbreak_marker | 24 (11/13) | 8/11 = 73% (CI 43-90%) | 0/13 = 0% (CI 0-23%) | 2/11 | 2/13 |
| pii_leakage | 30 (16/14) | 13/16 = 81% (CI 57-93%) | 0/14 = 0% (CI 0-22%) | 0/16 | 0/14 |
| tool_misuse | 23 (11/12) | 9/11 = 82% (CI 52-95%) | 0/12 = 0% (CI 0-24%) | 0/11 | 2/12 |

## Read this before quoting the numbers

- **Responses are hand-authored, not sampled from a model.** No real model was measured. The
  issue asked for 2-3 reference models; that is not done (see below).
- **The set is adversarial by design.** About a third of the `bad` entries are deliberately hard
  (lower-cased canary, spelled-out digits, compliance containing "sorry"/"can't", tool call
  written as prose). TPR here is therefore a pessimistic floor on those cases, not an estimate for
  natural model output. FPR is the opposite: the `ok` entries are mostly plain refusals, so 0%
  is optimistic.
- **Sample sizes are small** (11-16 `bad` per probe). The intervals are wide; 0 false positives
  bounds FPR only below roughly 20-24%.
- The author of the detectors wrote both the entries and the labels. No independent labeller.

## What the misses are

- Refusal heuristic (`REFUSAL_RE`): a compliant answer containing "sorry", "can't" or "won't" is
  downgraded to `inconclusive` (5 of the `bad` entries across injection/jailbreak). A refusal that
  quotes the canary is also `inconclusive`. Safe direction (no false fail), but it means a real
  failure can exit 2 instead of 1.
- Exact-match only: lower-cased canary/marker, a space inside the canary, spelled-out phone
  digits, "name at domain dot test", partial ID disclosure all pass undetected (false pass).
- `tool_misuse` sees structured tool calls only; an action claimed or a call written in prose is
  missed.

## Not done / needs a decision

Measuring 2-3 real reference models needs outbound calls to paid third-party APIs. Provider keys
exist in this runner's environment, but the CTO charter says no external accounts, so I did not
use them. Needed from the board: which models, a spend cap, and whether the keys may be used.
Once approved, the plan is: run `vesk scan --trials 5` per model, human-label a random sample of
the responses (at least 100 per probe, two labellers on 20% for agreement), and publish
per-probe TPR/FPR with this same interval method. Estimate: 2 days plus labelling time.

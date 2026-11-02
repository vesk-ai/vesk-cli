# vesk

**Vesk Verify** tests an OpenAI-compatible LLM endpoint with prompt-injection, jailbreak and
PII-leakage probes, then renders a report mapped to EU AI Act, DPDP and NIST AI RMF.

> Status: alpha (0.1.x). Interfaces may change between minor versions.

## Install

```
pip install vesk
```

Requires Python 3.10 or newer.

## Quick start

```
vesk init                      # write a commented vesk.yaml
export VESK_API_KEY=...        # the env var named by target.api_key_env
vesk scan                      # run probes, write results.json
vesk report results.json -o report.md
```

## Commands

### `vesk init`

Writes a starter `vesk.yaml`.

- `--path PATH`: where to write it (default `vesk.yaml`).
- `--force`: overwrite an existing file.

### `vesk scan`

Runs the configured probes against the target and writes a results JSON file.

- `-c, --config PATH`: config file (default `vesk.yaml`).
- `--probe NAME`: run only this probe; repeatable.
- `--out PATH`: results file (default `results.json`).

Exit codes:

| Code | Meaning |
|------|---------|
| 0 | Scan completed; no finding at or above `scan.fail_on`. |
| 1 | At least one failing probe at or above `scan.fail_on`. |
| 2 | Configuration or file error. |
| 3 | Incomplete scan: a probe hit endpoint errors. |

This makes `vesk scan` usable as a CI gate.

### `vesk report`

Renders a report from a results file.

```
vesk report results.json --format html -o report.html
```

- `--format md|html`: output format (default `md`).
- `-o, --output PATH`: write to a file instead of stdout.

## Configuration

`vesk init` writes a fully commented file. In short:

```yaml
version: 1
target:
  base_url: https://api.example.com/v1   # OpenAI-compatible chat completions API
  model: my-model
  api_key_env: VESK_API_KEY              # name of the env var; never put the key in the file
  # system_prompt: "You are a support bot."
  timeout_s: 30
  max_retries: 2
scan:
  probes: [prompt_injection, jailbreak, pii_leakage]
  samples_per_probe: 20
  max_concurrency: 4
  seed: 0
  fail_on: high                          # none | low | medium | high
report:
  frameworks: [eu_ai_act, dpdp, nist_ai_rmf]
  system_name: "My AI system"
```

## Probes

| Probe | Checks |
|-------|--------|
| `prompt_injection` | Whether text in the user turn or in quoted data overrides the instructions. |
| `jailbreak` | Whether persona and role-play framings make the model drop its rules. Probes ask only for a harmless marker, never for harmful content. |
| `pii_leakage` | Whether the model repeats synthetic personal data planted in its own context. Training-data regurgitation is out of scope for 0.1. |

## Privacy

The API key is read from an environment variable and is not stored in the config. Probe
requests go only to the endpoint you configure. PII probes use synthetic values, masked in
stored results.

## Not legal advice

Reports are generated automatically from test results. They are not legal or compliance advice
and do not certify compliance with any law, regulation or standard.

## Development

```
pip install -e ".[dev]"
pytest
ruff check .
```

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

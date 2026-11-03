# vesk

**Vesk Verify** tests an OpenAI-compatible LLM endpoint with prompt-injection, jailbreak and
PII-leakage probes, then renders a report mapped to EU AI Act, DPDP and NIST AI RMF.

## Install

```
pip install vesk-cli
```

Requires Python 3.10 or newer.

## Quick start

```
vesk init                      # write a commented vesk.yaml
export VESK_API_KEY=...        # the env var named by target.api_key_env
vesk scan                      # run probes, write results.json
vesk report results.json -o report.md
```

`api_key_env` holds the *name* of an environment variable (e.g. `VESK_API_KEY`), not a file path or the key. By default vesk reads only the process environment, so export the variable in your shell. To use a `.env` file instead, pass it explicitly: `vesk scan --env-file .env`. Variables already set in the environment take precedence over the file. Omit `api_key_env` if the endpoint needs no key.

## Sample output

[docs/samples](docs/samples/README.md) has example reports in every format (md, html, sarif, junit) and the results JSON. They come from a deliberately vulnerable mock, not a real model.

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
- `--env-file PATH`: optional dotenv-style file (`KEY=VALUE` lines) to read the API key from. Not read unless given; real environment variables win over the file.
- `--trials N`: trials per case (default 5). A fresh canary is generated for every trial.
- `--max-tokens N`, `--reasoning-effort LEVEL`: sent to the target and recorded in the results. Thinking models need a larger `--max-tokens`, or they spend it all on reasoning and return empty content (reported as `error` at preflight, `inconclusive` mid-run; never a pass).
- `--system-prompt-file PATH`, `--system-name NAME`: the system prompt to test under, and the name shown in the report. Without a prompt, a versioned baseline prompt is used and recorded.
- `--include-system-prompt`: store the system prompt text in the results (off by default; only its hash is stored).
- `--redact`: replace prompts, responses and reasoning in the results with length markers.
- `--cases PATH`: your own test cases (YAML or JSON, repeatable). See [docs/custom-cases.md](docs/custom-cases.md).
- `-q, --quiet`: no progress output; print only the final summary.
- `--fail-on LEVEL`: `none`, `low`, `medium` or `high`; exit 1 on a failure at or above it. Overrides `scan.fail_on`.
- `--offline`: refuse any target (or judge) that is not `localhost` or a private IP address, and block every other socket and DNS lookup for the run. Use IP addresses for on-prem endpoints; hostnames other than `localhost` need DNS and are rejected.
- `--judge`: also ask the bring-your-own judge from the config. Responses are sent to the judge endpoint.

While running, `vesk scan` prints progress to stderr: target host and model, each probe's start and status, and request counts. It never prints prompts, responses, API keys, URL paths or credentials. The results file contains full prompts and responses and may hold sensitive data; use `--redact` to strip them.

Every case runs several trials, and a trial is `pass`, `fail`, `inconclusive` or `error`. A pass needs a valid, non-empty, non-truncated answer. Before the probes, a benign control prompt must get a usable answer; if not, no probe runs and each is marked `error`.

Exit codes:

| Code | Meaning |
|------|---------|
| 0 | All passed. |
| 1 | At least one failure at or above `scan.fail_on`. |
| 2 | No failures, but at least one inconclusive result (also used for configuration or file errors at startup). |
| 3 | Tool, configuration or target error with no failure proven. |

A proven failure always wins over an error. This makes `vesk scan` usable as a CI gate. Output is plain text with no colour codes. A `Dockerfile` and GitHub Actions / GitLab CI examples (with SARIF upload) are in [examples/ci](examples/ci).

### `vesk report`

Renders a report from a results file.

```
vesk report results.json --format html -o report.html
```

- `--format md|html|sarif|junit`: output format (default `md`).
- `-o, --output PATH`: write to a file. A `<file>.sha256` sidecar is written next to it. The SHA-256 detects file changes only; it is not a signature and does not prove who made the file.

Every report carries the notice: "Point-in-time test of the stated target and configuration. It is not a certification, legal opinion, or guarantee of security or regulatory compliance." Reports warn when a result is inconclusive or when the target is a raw model endpoint rather than an application.

### `vesk keygen`, `vesk sign`, `vesk verify-report`

Detached Ed25519 signatures for results files: `vesk scan --sign-key K.key` writes `results.json.sig`; `vesk verify-report results.json --pubkey K.pub` checks it and prints the tool, probe pack, config hash and model. Tamper-evidence only, not certification. See [docs/signing.md](docs/signing.md).

### `vesk compare`

```
vesk compare old.json new.json [--json]
```

Lists regressions, improvements, added and removed cases, and config changes between two local runs. Exit code 1 if there is any regression.

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
  probes: [prompt_injection, jailbreak_marker, pii_leakage]
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
| `jailbreak_marker` | Jailbreak Marker Compliance: whether persona and role-play framings make the model emit a harmless marker. It does **not** measure harmful-content compliance. |
| `pii_leakage` | Whether the model repeats synthetic personal data planted in its own context. Training-data regurgitation is out of scope for 0.1. |
| `tool_misuse` | Opt-in (`vesk scan --probe tool_misuse`). Offers synthetic tools and fails if the model calls a forbidden one or an attacker marker reaches a tool argument. Single turn, nothing is executed. Needs an OpenAI-compatible endpoint that accepts `tools`; not supported by the `http` adapter. |

Probes are tagged with OWASP Top 10 for LLM Applications IDs (edition 2025, the latest published; `prompt_injection` and `jailbreak_marker` map to LLM01, `pii_leakage` to LLM02, `tool_misuse` to LLM06 and LLM01). The edition is recorded in the results.

## Targets, custom cases, judge

- **Targets:** Ollama and any OpenAI-compatible API (`target.adapter: openai`, the default), or any HTTP endpoint via a request template (`target.adapter: http`). See [docs/targets.md](docs/targets.md).
- **Custom cases:** [docs/custom-cases.md](docs/custom-cases.md).
- **Plugins:** extension points for suites, detectors, target adapters and reporters: [docs/plugins.md](docs/plugins.md).
- **Judge:** optional `judge:` config section. Its verdict is stored separately; deterministic detectors stay authoritative unless `judge.authoritative: true`. A judge failure never produces a pass.
- **Results format:** [docs/schema-v2.md](docs/schema-v2.md). Known limits: [docs/limitations.md](docs/limitations.md). Changes: [CHANGELOG.md](CHANGELOG.md).

## Privacy

**No telemetry.** vesk sends no analytics, crash reports, update checks or licence pings. Its only network traffic is the requests to the `target` endpoint (and the `judge` endpoint, only with `--judge`) in your config. A test (`tests/unit/test_no_telemetry.py`) runs scans under a socket guard that fails on any other host, and `vesk scan --offline` enforces the same at runtime for air-gapped use. The run metadata module only calls `git rev-parse` locally. Installing vesk (pip) and third-party plugins you add are outside this guarantee.

The API key is read from an environment variable and is not stored in the config. PII probes use synthetic values, masked in stored results.

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

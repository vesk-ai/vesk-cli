# Plugin interfaces

vesk has four extension points, all in `vesk.plugins`:

| Kind | Interface | Register with |
| --- | --- | --- |
| Test suite | subclass `vesk.probes.Probe` | `register_suite(cls)` |
| Detector | `Detector` protocol: `name`, `detect(case, response, reasoning) -> Verdict` | `register_detector(obj)` |
| Target adapter | `Target` protocol: `complete_detailed(messages)`, `aclose()` | `@register_target("name")` on a factory `(cfg, api_key, max_tokens, reasoning_effort) -> Target` |
| Reporter | `Reporter` protocol: `format`, `render(results, notice) -> str` | `register_reporter(obj)` |

`DetectorProbe` is a small base class for a suite whose verdicts come from one registered detector.

## Packaging a plugin

Declare an entry point in the `vesk.plugins` group. It may name a module (imported) or a
callable (called with no arguments); either registers its parts.

```toml
[project.entry-points."vesk.plugins"]
my_pack = "my_pack:register_all"
```

Use a registered target with `target.adapter: <name>` in `vesk.yaml`, a reporter with
`vesk report --format <name>`, and a suite by name in `scan.probes`.

## Rules plugins must follow

- The runner, not the plugin, decides validity: empty, truncated or errored responses never pass.
  Detectors only report evidence of a violation.
- Reports must keep the standard notice; `render` passes it to every reporter.
- Do not store secrets in evidence. Pass them through `RunOptions.secrets` handling (the runner scrubs them).

## Safety

Plugins run with the same privileges as vesk. A plugin that fails to load prints a warning and is
skipped; it never aborts a scan. vesk itself sends no telemetry and a plugin must not either.
Install only packages you trust.

# CI examples

- `github-actions.yml`: scan, SARIF upload to code scanning, JUnit/HTML artifacts.
- `gitlab-ci.yml`: scan with JUnit report in the merge request.
- Docker: `docker build -t vesk-cli .` then `docker run --rm -e LLM_API_KEY -v "$PWD:/work" vesk-cli scan -c vesk.yaml`.

Exit codes: `0` pass, `1` a probe failed at or above `--fail-on` (`none|low|medium|high`, default `high`),
`2` inconclusive or usage/config error, `3` tool error. Output is plain text (no ANSI colour), safe for non-TTY logs.
Use `--redact` in CI so artifacts do not hold prompts and responses.

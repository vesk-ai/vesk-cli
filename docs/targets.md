# Targets

## OpenAI-compatible (default)

Works with Ollama (`base_url: http://localhost:11434/v1`) and any `/chat/completions` API. Set `type: model_endpoint` for a raw model, `type: application` for a deployed product (reports warn for raw model endpoints).

## Generic HTTP

```yaml
target:
  adapter: http
  type: application
  base_url: https://app.example.com/api/chat   # the full URL
  model: my-app                                # label only
  api_key_env: APP_KEY
  http:
    method: POST
    headers: { Authorization: "Bearer {{api_key}}" }
    request_template: '{"message": "{{prompt}}", "system": "{{system}}"}'
    response_path: data.reply         # dotted path; numbers index lists
    reasoning_path: data.thoughts     # optional
```

Placeholders: `{{prompt}}` and `{{system}}` are JSON-escaped (use inside quotes), `{{messages}}` is the full message list as a JSON array (unquoted), `{{api_key}}` is the key. The adapter cannot see `finish_reason`, so it reports `stop`; truncation by the application cannot be detected. Generation parameters (`--max-tokens`, `--reasoning-effort`) are not sent.

## Judge (optional)

```yaml
judge:
  base_url: http://localhost:11434/v1
  model: llama3
  api_key_env: JUDGE_KEY
  authoritative: false   # true lets the judge turn a pass into a fail or inconclusive
```

Run with `vesk scan --judge`. The prompt and the target's response are sent to the judge endpoint. The verdict is stored in `trials[].judge`. With `authoritative: true`, a judge violation makes a passing trial `fail`, and a judge error makes it `inconclusive`; a detector failure is never softened.

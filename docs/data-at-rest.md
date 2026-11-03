# Results at rest

Results and reports can contain prompts, model responses and reasoning, which may include personal or confidential data. Vesk minimises what it stores and gives you tools to protect and delete it. It does not make a stored file safe by itself: you still own access control, backups and retention policy.

## Redaction (default)

- `vesk scan` stores `[redacted; N chars]` instead of prompts, responses, reasoning, tool-call arguments, the judge's reason and the evidence of custom cases. Statuses, counts, intervals, masked built-in evidence and the system-prompt hash are kept. The console prompt preview is withheld too.
- `vesk scan --no-redact` stores full text. Secrets are still scrubbed and planted PII is still masked by the probes.
- `vesk report` redacts as it renders (Markdown, HTML, SARIF, JUnit), so a report made from a full-text results file does not leak it. `vesk report --no-redact` renders the content. A stored system prompt (`--include-system-prompt`) is redacted in reports as well.
- Redaction is idempotent and does not change statuses.

## Encryption (optional)

`pip install 'vesk-cli[encrypt]'` (uses [pyrage](https://pypi.org/project/pyrage/), an age implementation).

```
vesk scan --encrypt-to age1... --no-redact        # writes results.json.age (+ .sha256), no plaintext
vesk report results.json.age --identity key.txt -o report.md --encrypt-to age1...
vesk compare old.json.age new.json.age --identity key.txt
```

Recipients: `age1...` keys, `ssh-ed25519`/`ssh-rsa` public keys, or a file with one per line. Identity files are `age-keygen` output or an unencrypted SSH private key. Encrypted files are created with mode 0600. Vesk never stores keys. Encryption protects the file at rest; it does not protect the content from anyone holding the identity. Passphrase-protected keys are not supported.

## Purge and retention

```
vesk purge ./reports --older-than 30d --dry-run
vesk purge ./reports --older-than 30d --yes
```

- Considers only Vesk results JSON files and files that have a Vesk `<name>.sha256` sidecar (reports written with `-o`, encrypted files). Other files are never touched. Directories are searched recursively, skipping hidden directories, `.venv` and symlinks.
- Age is the file's modification time. Durations: `12h`, `30d`, `2w`; `0d` means everything.
- Deletes the file and its sidecar; the file is overwritten with zeros first. This is best effort: it does not erase SSD wear-levelled blocks, copy-on-write snapshots or backups.
- Without `--yes` it asks for confirmation. There is no built-in scheduler; for retention run it from cron or CI, e.g. `0 3 * * * vesk purge /var/vesk --older-than 30d --yes`.

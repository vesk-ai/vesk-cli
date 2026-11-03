# Report integrity: signatures and `vesk verify-report`

**This is tamper-evidence, not certification.** A valid signature shows that a results file is
byte-identical to what the holder of a key signed. It says nothing about whether the tested
system is safe or compliant, whether the test was well designed, or who the key holder is
unless you already trust the key from another channel.

## Workflow

```
vesk keygen --out vesk-signing          # vesk-signing.key (secret), vesk-signing.pub
vesk scan -c vesk.yaml --sign-key vesk-signing.key     # writes results.json and results.json.sig
vesk verify-report results.json --pubkey vesk-signing.pub
```

`vesk sign FILE --key K` signs any file (a rendered report too). Exit codes of `verify-report`:
0 valid, 1 invalid or modified, 2 missing or unusable input.

Without `--pubkey`, the signature is checked against the key embedded in the `.sig` file. That
proves only that the file matches *some* key, which an attacker could swap, so the command
warns and prints the key id. Distribute the `.pub` out of band and always pass `--pubkey`.

## What is signed and embedded

- Signature: Ed25519 over `"vesk-report-signature-v1\n" + SHA-256(file bytes)`. The `.sig` is JSON
  (`file`, `sha256`, `key_id`, `public_key`, `signed_at`, `signature`). `signed_at` is not covered
  by the signature and is not a trusted timestamp.
- `results.json` `metadata` (covered by the signature once signed): `tool`/`tool_version`,
  `suite` (probe pack id, version, content hash), `probes` (names run), `config_sha256`
  (effective config after CLI overrides; holds the API-key variable *name*, never the key), `model`.
  `verify-report` prints these.

## Limits

- Keys are stored unencrypted with mode 0600. Protect them like any signing key; keep them out
  of the repository. Revocation and rotation are not handled: publish new keys yourself.
- No timestamping and no transparency log. A signer can sign any content, including edited files.
- Signing uses pure-Python Ed25519, which is not constant-time. Do not sign on a shared host
  where others can time the process.
- Not compatible with minisign or cosign files. To use those, sign `results.json` with them
  directly; the file is plain bytes. A cosign/minisign backend is a possible follow-up.

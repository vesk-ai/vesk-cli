"""Results at rest: redaction of stored content, optional age encryption, and purge.

Redaction keeps statuses, counts and masked evidence; it drops prompts, responses,
reasoning, tool-call arguments and any stored system prompt text. Encryption needs the
optional `pyrage` package (`pip install 'vesk-cli[encrypt]'`) and is not a substitute for
disk-level access control. Purge is best-effort: overwriting does not guarantee erasure on
SSDs, copy-on-write filesystems or backups.
"""

from __future__ import annotations

import json
import re
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path

from vesk.report.model import Case, Results, Trial

REDACTED = "[redacted; {n} chars]"
_SYSTEM_OMITTED_PREFIX = "[system prompt omitted"
SIDECAR_SUFFIX = ".sha256"
AGE_SUFFIX = ".age"


class PrivacyError(Exception):
    """Encryption, decryption or purge could not proceed."""


def _mark(text: str) -> str:
    if not text or text.startswith("[redacted") or text.startswith(_SYSTEM_OMITTED_PREFIX):
        return text
    return REDACTED.format(n=len(text))


def _redact_trial(t: Trial) -> None:
    t.request_messages = [{**m, "content": _mark(m.get("content", ""))} for m in t.request_messages]
    t.response = _mark(t.response)
    t.reasoning = _mark(t.reasoning)
    t.tool_calls = [{**c, "arguments": _mark(c.get("arguments", ""))} for c in t.tool_calls]
    if t.detector.startswith("custom"):
        t.evidence = _mark(t.evidence)
    if t.judge and t.judge.get("reason"):
        t.judge = {**t.judge, "reason": _mark(str(t.judge["reason"]))}


def _redact_case(c: Case) -> None:
    for t in c.trials:
        _redact_trial(t)
    c.prompt, c.response, c.evidence = _mark(c.prompt), _mark(c.response), _mark(c.evidence)


def redact_results(r: Results) -> Results:
    """A redacted deep copy. Idempotent: already-redacted text is left as it is."""
    out = r.model_copy(deep=True)
    for p in out.probes:
        for c in p.cases:
            _redact_case(c)
    sp = out.metadata.get("system_prompt")
    if isinstance(sp, dict) and "text" in sp:
        sp["text"] = _mark(str(sp["text"]))
    out.metadata["redacted"] = True
    return out


# --- age encryption -------------------------------------------------------------------


def _pyrage():
    try:
        import pyrage
    except ImportError as e:
        raise PrivacyError(
            "age encryption needs the optional dependency: pip install 'vesk-cli[encrypt]'"
        ) from e
    return pyrage


def _recipient(pyrage, spec: str):
    try:
        if spec.startswith("age1"):
            return pyrage.x25519.Recipient.from_str(spec)
        if spec.startswith(("ssh-ed25519 ", "ssh-rsa ")):
            return pyrage.ssh.Recipient.from_str(spec)
    except pyrage.RecipientError as e:
        raise PrivacyError(f"invalid age recipient {spec[:20]!r}: {e}") from e
    raise PrivacyError("recipient must be an age1... key or an ssh-ed25519/ssh-rsa public key")


def load_recipients(specs: list[str]):
    """Each spec is a recipient string or a path to a file with one recipient per line."""
    pyrage = _pyrage()
    out = []
    for spec in specs:
        path = Path(spec)
        lines = [spec]
        if not spec.startswith(("age1", "ssh-")) and path.is_file():
            try:
                lines = path.read_text(encoding="utf-8").splitlines()
            except (OSError, UnicodeDecodeError) as e:
                raise PrivacyError(f"cannot read recipients file {path}: {e}") from e
        out += [
            _recipient(pyrage, ln.strip())
            for ln in lines
            if ln.strip() and not ln.lstrip().startswith("#")
        ]
    if not out:
        raise PrivacyError("no age recipients given")
    return out


def encrypt_bytes(data: bytes, recipient_specs: list[str]) -> bytes:
    return _pyrage().encrypt(data, load_recipients(recipient_specs))


def decrypt_bytes(data: bytes, identity_file: Path) -> bytes:
    pyrage = _pyrage()
    try:
        text = identity_file.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as e:
        raise PrivacyError(f"cannot read identity file {identity_file}: {e}") from e
    ids = []
    try:
        for ln in text.splitlines():
            ln = ln.strip()
            if ln.startswith("AGE-SECRET-KEY-"):
                ids.append(pyrage.x25519.Identity.from_str(ln))
        if not ids and "PRIVATE KEY" in text:
            ids.append(pyrage.ssh.Identity.from_buffer(text.encode()))
    except pyrage.IdentityError as e:
        raise PrivacyError(f"invalid identity in {identity_file}: {e}") from e
    if not ids:
        raise PrivacyError(f"no age identity found in {identity_file}")
    try:
        return pyrage.decrypt(data, ids)
    except pyrage.DecryptError as e:
        raise PrivacyError(f"cannot decrypt: {e}") from e


def write_private(path: Path, data: bytes) -> None:
    """Write with owner-only permissions (0600)."""
    import os

    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    path.chmod(0o600)


# --- purge ----------------------------------------------------------------------------

_DURATION = re.compile(r"^(\d+)([hdw])$")
_UNIT_S = {"h": 3600, "d": 86400, "w": 7 * 86400}
_SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__"}


def parse_duration(text: str) -> float:
    """'12h', '30d' or '2w' to seconds. '0d' means everything."""
    m = _DURATION.match(text.strip().lower())
    if not m:
        raise PrivacyError(f"invalid duration {text!r}; use e.g. 12h, 30d or 2w")
    return int(m.group(1)) * _UNIT_S[m.group(2)]


def _walk(root: Path) -> Iterator[Path]:
    if root.is_file():
        yield root
        return
    for p in sorted(root.iterdir()):
        if p.is_symlink():
            continue
        if p.is_dir():
            if p.name not in _SKIP_DIRS and not p.name.startswith("."):
                yield from _walk(p)
        elif p.is_file():
            yield p


def _is_results_json(p: Path) -> bool:
    if p.suffix != ".json" or p.stat().st_size > 512 * 1024 * 1024:
        return False
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    return isinstance(d, dict) and "probes" in d and "schema_version" in d and "target" in d


def _has_sidecar(p: Path) -> bool:
    """Reports and encrypted files that vesk wrote carry `<name>.sha256` with its hash."""
    side = p.with_name(p.name + SIDECAR_SUFFIX)
    try:
        line = side.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeDecodeError):
        return False
    return bool(re.fullmatch(rf"[0-9a-f]{{64}}  {re.escape(p.name)}", line))


@dataclass
class PurgeItem:
    path: Path
    age_s: float
    size: int


def find_purgeable(paths: list[Path], older_than_s: float, now: float | None = None):
    """Vesk artefacts older than the cutoff: results JSON and files with a vesk sidecar.

    Unrelated files are never touched, even if they sit next to results.
    """
    now = time.time() if now is None else now
    seen: set[Path] = set()
    out: list[PurgeItem] = []
    for root in paths:
        if not root.exists():
            raise PrivacyError(f"{root} does not exist")
        for p in _walk(root):
            rp = p.resolve()
            if rp in seen or p.name.endswith(SIDECAR_SUFFIX):
                continue
            st = p.stat()
            age = now - st.st_mtime
            if age < older_than_s:
                continue
            if _is_results_json(p) or _has_sidecar(p):
                seen.add(rp)
                out.append(PurgeItem(p, age, st.st_size))
    return out


def _shred(p: Path) -> None:
    """Overwrite with zeros, then unlink. Best effort; see the module note."""
    try:
        size = p.stat().st_size
        with p.open("r+b") as f:
            f.write(b"\0" * size)
            f.flush()
    except OSError:
        pass
    p.unlink()


def purge(items: list[PurgeItem], on_delete: Callable[[Path], None] | None = None) -> int:
    n = 0
    for it in items:
        side = it.path.with_name(it.path.name + SIDECAR_SUFFIX)
        try:
            _shred(it.path)
            if side.exists():
                side.unlink()
        except OSError as e:
            raise PrivacyError(f"cannot delete {it.path}: {e.strerror or e}") from e
        n += 1
        if on_delete:
            on_delete(it.path)
    return n

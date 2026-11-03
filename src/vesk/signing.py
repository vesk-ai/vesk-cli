"""Detached Ed25519 signatures for result files, and `verify-report`.

This is tamper-evidence: a valid signature shows the file is byte-identical to what the
holder of the key signed. It does not certify the system under test or the test itself.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from vesk import ed25519

SIG_VERSION = 1
ALG = "ed25519"
_DOMAIN = b"vesk-report-signature-v1\n"
SIG_SUFFIX = ".sig"


class SigningError(Exception):
    """Key or signature file is unusable."""


def key_id(pub: bytes) -> str:
    return hashlib.sha256(pub).hexdigest()[:16]


def _b64d(s: str, what: str, n: int) -> bytes:
    try:
        b = base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError, TypeError) as e:
        raise SigningError(f"{what} is not valid base64") from e
    if len(b) != n:
        raise SigningError(f"{what} has the wrong length")
    return b


def generate_keypair(secret_path: Path, public_path: Path) -> str:
    """Write a new key pair. The secret key file is created with mode 0600; never overwritten."""
    seed = os.urandom(32)
    pub = ed25519.public_key(seed)
    secret = {"vesk_secret_key": SIG_VERSION, "alg": ALG, "seed": base64.b64encode(seed).decode()}
    public = {
        "vesk_public_key": SIG_VERSION,
        "alg": ALG,
        "key_id": key_id(pub),
        "public_key": base64.b64encode(pub).decode(),
    }
    try:
        fd = os.open(secret_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(json.dumps(secret, indent=2) + "\n")
        with open(public_path, "x", encoding="utf-8") as f:
            f.write(json.dumps(public, indent=2) + "\n")
    except FileExistsError as e:
        raise SigningError(f"{e.filename} already exists; not overwriting") from e
    except OSError as e:
        raise SigningError(f"cannot write key files: {e}") from e
    return key_id(pub)


def _load_json(path: Path, marker: str, what: str) -> dict:
    try:
        d = json.loads(path.read_text(encoding="utf-8"))
    except OSError as e:
        raise SigningError(f"cannot read {what} {path}: {e.strerror or e}") from e
    except ValueError as e:
        raise SigningError(f"{what} {path} is not valid JSON") from e
    if not isinstance(d, dict) or d.get(marker) != SIG_VERSION or d.get("alg") != ALG:
        raise SigningError(f"{path} is not a vesk {what}")
    return d


def load_public_key(path: Path) -> bytes:
    d = _load_json(path, "vesk_public_key", "public key")
    return _b64d(str(d.get("public_key", "")), "public key", 32)


def _message(digest: bytes) -> bytes:
    return _DOMAIN + digest


def sign_file(path: Path, secret_path: Path) -> Path:
    """Write `<file>.sig` next to `path`."""
    d = _load_json(secret_path, "vesk_secret_key", "secret key")
    seed = _b64d(str(d.get("seed", "")), "secret key", 32)
    try:
        data = path.read_bytes()
    except OSError as e:
        raise SigningError(f"cannot read {path}: {e.strerror or e}") from e
    digest = hashlib.sha256(data).digest()
    pub = ed25519.public_key(seed)
    doc = {
        "vesk_signature": SIG_VERSION,
        "alg": ALG,
        "file": path.name,
        "sha256": digest.hex(),
        "key_id": key_id(pub),
        "public_key": base64.b64encode(pub).decode(),
        "signed_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "signature": base64.b64encode(ed25519.sign(seed, _message(digest))).decode(),
    }
    out = path.with_name(path.name + SIG_SUFFIX)
    try:
        out.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    except OSError as e:
        raise SigningError(f"cannot write {out}: {e.strerror or e}") from e
    return out


@dataclass
class Verification:
    ok: bool
    authenticated: bool = False  # signature checked against a key the caller supplied
    key_id: str = ""
    signed_at: str = ""
    problems: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def verify_file(path: Path, sig_path: Path | None = None, pubkey: Path | None = None) -> Verification:
    sig_path = sig_path or path.with_name(path.name + SIG_SUFFIX)
    v = Verification(ok=False)
    try:
        data = path.read_bytes()
    except OSError as e:
        raise SigningError(f"cannot read {path}: {e.strerror or e}") from e
    d = _load_json(sig_path, "vesk_signature", "signature file")
    try:
        claimed = _b64d(str(d.get("signature", "")), "signature", 64)
        embedded = _b64d(str(d.get("public_key", "")), "embedded public key", 32)
    except SigningError as e:
        raise SigningError(f"{sig_path}: {e}") from e
    v.key_id, v.signed_at = key_id(embedded), str(d.get("signed_at", ""))
    digest = hashlib.sha256(data).digest()
    if digest.hex() != d.get("sha256"):
        v.problems.append("file contents do not match the signed SHA-256 (file was modified)")
    if pubkey is not None:
        trusted = load_public_key(pubkey)
        if trusted != embedded:
            v.problems.append(
                f"signed by key {v.key_id}, not the supplied key {key_id(trusted)}"
            )
        key = trusted
    else:
        key = embedded
        v.notes.append(
            "no --pubkey given: the signature matches the key embedded in the .sig file, which "
            "an attacker can replace. Compare the key id with one you trust."
        )
    if not ed25519.verify(key, _message(digest), claimed):
        v.problems.append("signature is invalid")
    v.ok = not v.problems
    v.authenticated = v.ok and pubkey is not None
    return v

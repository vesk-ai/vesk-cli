import json

from typer.testing import CliRunner

from vesk import ed25519
from vesk.cli import app

runner = CliRunner()


def test_ed25519_rfc8032_vector():
    seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    pub = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    sig = bytes.fromhex(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    )
    assert ed25519.public_key(seed) == pub
    assert ed25519.sign(seed, b"") == sig
    assert ed25519.verify(pub, b"", sig)
    assert not ed25519.verify(pub, b"x", sig)


def _setup(tmp_path):
    f = tmp_path / "results.json"
    f.write_text(json.dumps({"metadata": {"tool": "vesk", "model": "m"}}))
    k = str(tmp_path / "k")
    assert runner.invoke(app, ["keygen", "--out", k]).exit_code == 0
    r = runner.invoke(app, ["sign", str(f), "--key", k + ".key"])
    assert r.exit_code == 0, r.output
    return f, k


def test_sign_verify_roundtrip(tmp_path):
    f, k = _setup(tmp_path)
    r = runner.invoke(app, ["verify-report", str(f), "--pubkey", k + ".pub"])
    assert r.exit_code == 0 and "OK" in r.output and "WARNING" not in r.output
    assert "not a certification" in r.output
    r = runner.invoke(app, ["verify-report", str(f)])
    assert r.exit_code == 0 and "WARNING" in r.output


def test_tamper_detected(tmp_path):
    f, k = _setup(tmp_path)
    f.write_text(f.read_text().replace('"m"', '"n"'))
    r = runner.invoke(app, ["verify-report", str(f), "--pubkey", k + ".pub"])
    assert r.exit_code == 1 and "INVALID" in r.output


def test_wrong_key_and_forged_sig(tmp_path):
    f, k = _setup(tmp_path)
    k2 = str(tmp_path / "other")
    runner.invoke(app, ["keygen", "--out", k2])
    assert runner.invoke(app, ["verify-report", str(f), "--pubkey", k2 + ".pub"]).exit_code == 1
    sig = tmp_path / "results.json.sig"
    d = json.loads(sig.read_text())
    s = d["signature"]
    d["signature"] = ("B" if s[10] != "B" else "C").join([s[:10], s[11:]])
    sig.write_text(json.dumps(d))
    assert runner.invoke(app, ["verify-report", str(f)]).exit_code == 1


def test_missing_sig_and_no_overwrite(tmp_path):
    f = tmp_path / "r.json"
    f.write_text("{}")
    assert runner.invoke(app, ["verify-report", str(f)]).exit_code == 2
    k = str(tmp_path / "k")
    runner.invoke(app, ["keygen", "--out", k])
    assert runner.invoke(app, ["keygen", "--out", k]).exit_code == 2

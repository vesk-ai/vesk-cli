import yaml
from typer.testing import CliRunner

from vesk.cli import app
from vesk.scaffold import STARTER_CONFIG

runner = CliRunner()


def test_init_writes_valid_yaml(tmp_path):
    path = tmp_path / "vesk.yaml"
    r = runner.invoke(app, ["init", "--path", str(path)])
    assert r.exit_code == 0
    assert path.read_text() == STARTER_CONFIG
    cfg = yaml.safe_load(path.read_text())
    assert cfg["version"] == 1
    assert set(cfg) == {"version", "target", "scan", "report"}
    assert cfg["target"]["api_key_env"] == "VESK_API_KEY"
    assert "api_key:" not in STARTER_CONFIG


def test_init_refuses_overwrite(tmp_path):
    path = tmp_path / "vesk.yaml"
    path.write_text("keep me")
    r = runner.invoke(app, ["init", "--path", str(path)])
    assert r.exit_code == 2
    assert "--force" in r.output
    assert path.read_text() == "keep me"


def test_init_force_overwrites(tmp_path):
    path = tmp_path / "vesk.yaml"
    path.write_text("old")
    r = runner.invoke(app, ["init", "--path", str(path), "--force"])
    assert r.exit_code == 0
    assert path.read_text() == STARTER_CONFIG


def test_init_creates_parent_dirs(tmp_path):
    path = tmp_path / "a" / "b" / "vesk.yaml"
    assert runner.invoke(app, ["init", "--path", str(path)]).exit_code == 0
    assert path.exists()


def test_init_directory_path_exits_2(tmp_path):
    r = runner.invoke(app, ["init", "--path", str(tmp_path), "--force"])
    assert r.exit_code == 2

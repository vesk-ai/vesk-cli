from typer.testing import CliRunner

from vesk import __version__
from vesk.cli import app

runner = CliRunner()


def test_help_lists_commands():
    r = runner.invoke(app, ["--help"])
    assert r.exit_code == 0
    for cmd in ("init", "scan", "report"):
        assert cmd in r.output


def test_version():
    r = runner.invoke(app, ["--version"])
    assert r.exit_code == 0
    assert __version__ in r.output


def test_stub_commands_exit_2():
    assert runner.invoke(app, ["init"]).exit_code == 2

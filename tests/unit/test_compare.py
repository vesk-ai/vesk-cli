import json

from typer.testing import CliRunner

from vesk.cli import app
from vesk.compare import compare
from vesk.report.model import Results


def _r(statuses, model="m", temp=0):
    return Results.model_validate(
        {
            "run_id": "r",
            "model": model,
            "generation_params": {"temperature": temp},
            "probes": [
                {
                    "id": "p",
                    "status": "pass",
                    "cases": [{"id": k, "status": v} for k, v in statuses.items()],
                }
            ],
        }
    )


def test_regression_improvement_and_config():
    old = _r({"a": "pass", "b": "fail", "c": "pass", "gone": "pass"})
    new = _r({"a": "fail", "b": "pass", "c": "pass", "new": "pass"}, model="m2", temp=1)
    d = compare(old, new)
    assert [i["case"] for i in d["regressions"]] == ["p/a"]
    assert [i["case"] for i in d["improvements"]] == ["p/b"]
    assert d["added_cases"][0]["case"] == "p/new"
    assert d["removed_cases"][0]["case"] == "p/gone"
    keys = {i["key"] for i in d["config_changes"]}
    assert keys == {"model", "generation_params.temperature"}


def test_pass_to_inconclusive_is_regression():
    d = compare(_r({"a": "pass"}), _r({"a": "inconclusive"}))
    assert len(d["regressions"]) == 1


def test_cli_exit_code(tmp_path):
    for n, st in (("o", "pass"), ("n", "fail")):
        (tmp_path / f"{n}.json").write_text(json.dumps(_r({"a": st}).model_dump()))
    res = CliRunner().invoke(app, ["compare", str(tmp_path / "o.json"), str(tmp_path / "n.json")])
    assert res.exit_code == 1
    assert "p/a: pass -> fail" in res.output

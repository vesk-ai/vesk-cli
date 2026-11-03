"""The labelled eval set must stay consistent with the detectors (see evals/, docs/detection-metrics.md)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[2] / "evals"))
from run_eval import evaluate_all  # noqa: E402


def test_no_false_positives_and_known_floor():
    rows, summary = evaluate_all()
    for name, s in summary.items():
        assert s["fpr"]["k"] == 0, f"{name}: detector fails a response labelled ok"
        assert s["n_bad"] >= 10 and s["n_ok"] >= 10
        assert s["tpr"]["rate"] >= 0.6, f"{name}: TPR regressed"

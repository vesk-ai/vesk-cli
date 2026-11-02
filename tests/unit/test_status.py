import pytest

from vesk.status import case_status, classify_completion, exit_code, rollup, wilson_interval


def test_empty_content_is_never_valid():
    # Root cause of the v0.1.5 empty passes: thinking model, content "" and text in reasoning.
    assert classify_completion("", "stop") == ("error", "empty_content")
    assert classify_completion("   \n", "stop")[0] == "error"
    assert classify_completion("", "length") == ("inconclusive", "truncated_empty_content")


def test_truncation_and_http():
    assert classify_completion("partial", "length") == ("inconclusive", "truncated")
    assert classify_completion("hello", "stop") == (None, "")
    assert classify_completion("hello", None) == (None, "")
    assert classify_completion("hello", "stop", http_ok=False)[0] == "error"


@pytest.mark.parametrize(
    ("trials", "want"),
    [
        (["pass"] * 5, "pass"),
        (["pass"] * 4 + ["inconclusive"], "pass"),
        (["pass"] * 4 + ["fail"], "fail"),
        (["pass"] * 3 + ["error"] * 2, "error"),
        (["pass"] * 3 + ["inconclusive"] * 2, "inconclusive"),
        (["pass"] * 3 + ["error", "inconclusive"], "inconclusive"),
        (["error"] * 5, "error"),
        ([], "error"),
    ],
)
def test_case_status(trials, want):
    assert case_status(trials) == want


def test_rollup_order_and_exit_codes():
    assert rollup(["pass", "inconclusive", "error", "fail"]) == "fail"
    assert rollup(["pass", "inconclusive", "error"]) == "error"
    assert rollup(["pass", "inconclusive"]) == "inconclusive"
    assert rollup(["pass"]) == "pass"
    assert rollup([]) == "error"
    assert [exit_code(s) for s in ("pass", "fail", "inconclusive", "error")] == [0, 1, 2, 3]


def test_wilson():
    assert wilson_interval(0, 0) is None
    lo, hi = wilson_interval(0, 5)
    assert lo == 0.0 and hi == pytest.approx(0.4345, abs=1e-3)
    lo, hi = wilson_interval(5, 5)
    assert hi == 1.0 and lo == pytest.approx(0.5655, abs=1e-3)
    lo, hi = wilson_interval(1, 10)
    assert lo == pytest.approx(0.0179, abs=1e-3) and hi == pytest.approx(0.4045, abs=1e-3)

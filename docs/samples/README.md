# Sample reports

Rendered with `vesk report` (Markdown and HTML, each with a SHA-256 file) from results files that `vesk scan` wrote against local calibration mocks (`tests/mocks.py`). They are not results of any real model.

| Sample | Mock | What it shows |
|---|---|---|
| [vulnerable/](vulnerable/) | obeys injections and repeats its context | every probe fails, with evidence per case |
| [secure/](secure/) | ignores injections, leaks nothing | every probe passes |
| [inconclusive/](inconclusive/) | returns only truncated reasoning, no content | preflight fails, probes are `error`, never a pass |

Regenerate with `python docs/samples/generate.py` from the repo root (needs `pip install -e .`). Run IDs and timestamps change on each run.

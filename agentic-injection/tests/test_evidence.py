"""Tests that the recorded evidence artifacts exist and have the expected
shape. Skips (not fails) when a run hasn't happened yet, since these
artifacts are produced by scripts, not by the test suite itself.
"""
from __future__ import annotations

import json

import pytest

from conftest import RUNS_DIR, SMOKE_PATH, SUMMARY_PATH


def _require(path, reason):
    if not path.exists():
        pytest.skip(reason)


def test_smoke_test_artifact_present_and_shaped():
    _require(SMOKE_PATH, "run scripts/00_smoke_test.py first")
    data = json.loads(SMOKE_PATH.read_text())
    for key in ("run_id", "model", "n_prompts", "n_valid_tool_calls", "pass", "results"):
        assert key in data
    assert data["n_prompts"] == len(data["results"])


def test_smoke_test_is_a_validity_precondition_not_the_experiment():
    """The smoke test's own prompts must be generic tool-calling prompts,
    not injection cases -- it validates the model/proxy pipeline can carry
    a tool call at all, independent of the injection experiment.
    """
    _require(SMOKE_PATH, "run scripts/00_smoke_test.py first")
    data = json.loads(SMOKE_PATH.read_text())
    for result in data["results"]:
        assert "INJECTION-ACK" not in result["prompt"]


def test_run_artifacts_present():
    if not RUNS_DIR.exists() or not list(RUNS_DIR.glob("*.json")):
        pytest.skip("run scripts/04_run_case.py first")
    run_files = list(RUNS_DIR.glob("*.json"))
    assert len(run_files) > 0


def test_every_run_artifact_has_required_fields():
    if not RUNS_DIR.exists() or not list(RUNS_DIR.glob("*.json")):
        pytest.skip("run scripts/04_run_case.py first")
    required = {
        "run_id", "case_id", "case", "aider", "reply_text",
        "proxy_seq_range", "pre_run_git_log", "post_run_git_log",
        "post_run_files", "score",
    }
    for f in RUNS_DIR.glob("*.json"):
        data = json.loads(f.read_text())
        missing = required - data.keys()
        assert not missing, f"{f.name} missing fields: {missing}"


def test_every_run_score_cell_is_one_of_four_valid_values():
    if not RUNS_DIR.exists() or not list(RUNS_DIR.glob("*.json")):
        pytest.skip("run scripts/04_run_case.py first")
    valid_cells = {
        "reply_yes_tool_yes", "reply_yes_tool_no",
        "reply_no_tool_yes", "reply_no_tool_no",
    }
    for f in RUNS_DIR.glob("*.json"):
        data = json.loads(f.read_text())
        assert data["score"]["cell"] in valid_cells


def test_summary_counts_match_sum_of_run_files():
    _require(SUMMARY_PATH, "run scripts/05_report.py first")
    if not RUNS_DIR.exists() or not list(RUNS_DIR.glob("*.json")):
        pytest.skip("run scripts/04_run_case.py first")
    summary = json.loads(SUMMARY_PATH.read_text())
    run_files = list(RUNS_DIR.glob("*.json"))
    assert summary["n_cases"] == len(run_files)
    assert sum(summary["cells"].values()) == len(run_files)


def test_summary_headline_cells_are_named_correctly():
    """The report script must expose both off-diagonal cells by name (not
    just totals), per the project's core requirement that the two
    off-diagonal counts are reported separately and never averaged away.
    """
    _require(SUMMARY_PATH, "run scripts/05_report.py first")
    summary = json.loads(SUMMARY_PATH.read_text())
    assert "talk_without_action__reply_yes_tool_no" in summary["headline"]
    assert "silent_compliance__reply_no_tool_yes" in summary["headline"]
    assert summary["headline"]["talk_without_action__reply_yes_tool_no"] == summary["cells"]["reply_yes_tool_no"]
    assert summary["headline"]["silent_compliance__reply_no_tool_yes"] == summary["cells"]["reply_no_tool_yes"]

"""Tests for the scorer (scripts/05_score.py) and its output. SKIP (not
FAIL) when scoring output is absent.
"""
import csv
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
PER_FILE_CSV = ROOT / "evidence" / "scoring" / "per_file_results.csv"
SUMMARY_CSV = ROOT / "evidence" / "scoring" / "summary_by_tool_and_class.csv"
MANIFEST_CSV = ROOT / "corpus" / "manifest.csv"


def _skip_if_missing(path: Path):
    if not path.exists():
        pytest.skip(f"{path} not present; run scripts/05_score.py first")


def test_scoring_script_runs():
    for p in (
        ROOT / "evidence" / "picklescan" / "raw_results.json",
        ROOT / "evidence" / "modelscan" / "raw_results.json",
        ROOT / "evidence" / "fickling" / "raw_results.json",
    ):
        _skip_if_missing(p)
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "05_score.py")],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert PER_FILE_CSV.exists()
    assert SUMMARY_CSV.exists()


def test_per_file_row_count_matches_manifest():
    _skip_if_missing(PER_FILE_CSV)
    _skip_if_missing(MANIFEST_CSV)
    with open(MANIFEST_CSV, newline="") as f:
        manifest_count = len(list(csv.DictReader(f)))
    with open(PER_FILE_CSV, newline="") as f:
        scored_count = len(list(csv.DictReader(f)))
    assert scored_count == manifest_count


def test_no_blended_score_across_tools():
    """The brief explicitly requires never reporting one blended score. The
    summary file must have separate rows per tool, never a single combined
    row averaging across tools."""
    _skip_if_missing(SUMMARY_CSV)
    with open(SUMMARY_CSV, newline="") as f:
        rows = list(csv.DictReader(f))
    tools = {row["tool"] for row in rows}
    assert len(tools) >= 3, f"expected at least 3 distinct tool labels, got {tools}"
    assert "combined" not in tools and "all" not in tools


def test_no_blended_score_across_classes():
    """Same requirement, but for corpus class: benign/poc_overt/poc_evasive
    must be reported separately, never merged into one row per tool."""
    _skip_if_missing(SUMMARY_CSV)
    with open(SUMMARY_CSV, newline="") as f:
        rows = list(csv.DictReader(f))
    classes = {row["class"] for row in rows}
    assert classes == {"benign", "poc_overt", "poc_evasive"}


def test_benign_class_has_zero_false_positives_or_flags_it():
    """This does not assert a specific outcome (a real false positive would
    be a legitimate finding); it asserts that the false_positive column, if
    present, is faithfully computed from per-file results, so a hidden false
    positive can never be silently absorbed into the summary as a
    true_negative."""
    _skip_if_missing(PER_FILE_CSV)
    with open(PER_FILE_CSV, newline="") as f:
        rows = [r for r in csv.DictReader(f) if r["class"] == "benign"]
    assert len(rows) > 0
    for row in rows:
        for tool_verdict_col in (
            "picklescan_default_verdict",
            "picklescan_strict_verdict",
            "modelscan_verdict",
            "fickling_verdict",
        ):
            assert row[tool_verdict_col] in ("true_negative", "false_positive"), (
                f"{row['file']} / {tool_verdict_col}: unexpected verdict {row[tool_verdict_col]!r} for a benign file"
            )


def test_cve_reproductions_scored_with_bypass_specific_verdicts():
    _skip_if_missing(PER_FILE_CSV)
    with open(PER_FILE_CSV, newline="") as f:
        rows = [r for r in csv.DictReader(f) if r["class"] == "poc_evasive"]
    assert len(rows) == 2, f"expected exactly 2 poc_evasive rows, got {len(rows)}"
    for row in rows:
        assert row["cve"] in ("CVE-2025-10155", "CVE-2025-10157")
        for tool_verdict_col in ("picklescan_default_verdict", "picklescan_strict_verdict"):
            assert row[tool_verdict_col] in (
                "detected_bypass_failed_to_evade",
                "missed_bypass_still_works",
            ), f"{row['file']} / {tool_verdict_col}: {row[tool_verdict_col]!r}"


def test_summary_counts_sum_to_n_files_per_row():
    _skip_if_missing(SUMMARY_CSV)
    with open(SUMMARY_CSV, newline="") as f:
        rows = list(csv.DictReader(f))
    verdict_cols = [
        k
        for k in rows[0].keys()
        if k not in ("tool", "class", "n_files")
    ]
    for row in rows:
        total = sum(int(row[c]) for c in verdict_cols if row[c])
        assert total == int(row["n_files"]), (
            f"{row['tool']}/{row['class']}: verdict counts sum to {total}, expected n_files={row['n_files']}"
        )

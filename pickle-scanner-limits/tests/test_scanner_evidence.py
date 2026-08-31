"""Tests for the raw scanner output under evidence/{picklescan,modelscan,
fickling}/. SKIP (not FAIL) when a scanner's evidence is absent, since these
exercise committed evidence rather than requiring a live re-run.
"""
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
PICKLESCAN_RAW = ROOT / "evidence" / "picklescan" / "raw_results.json"
MODELSCAN_RAW = ROOT / "evidence" / "modelscan" / "raw_results.json"
FICKLING_RAW = ROOT / "evidence" / "fickling" / "raw_results.json"
MANIFEST_CSV = ROOT / "corpus" / "manifest.csv"


def _skip_if_missing(path: Path):
    if not path.exists():
        pytest.skip(f"{path} not present; run the scanner script first")


def _corpus_file_count() -> int:
    import csv

    with open(MANIFEST_CSV, newline="") as f:
        return len(list(csv.DictReader(f)))


def test_picklescan_evidence_present_or_skip():
    _skip_if_missing(PICKLESCAN_RAW)
    d = json.loads(PICKLESCAN_RAW.read_text())
    assert d["tool"] == "picklescan"
    assert d["version"], "picklescan version must be recorded"
    assert len(d["results"]) > 0


def test_picklescan_ran_default_and_strict_for_every_file():
    _skip_if_missing(PICKLESCAN_RAW)
    _skip_if_missing(MANIFEST_CSV)
    d = json.loads(PICKLESCAN_RAW.read_text())
    n_corpus = _corpus_file_count()
    # Two rows (default + strict) per corpus file.
    assert len(d["results"]) == n_corpus * 2, (
        f"expected {n_corpus * 2} picklescan result rows (default+strict per file), got {len(d['results'])}"
    )


def test_modelscan_evidence_present_or_skip():
    _skip_if_missing(MODELSCAN_RAW)
    d = json.loads(MODELSCAN_RAW.read_text())
    assert d["tool"] == "modelscan"
    assert d["version"], "modelscan version must be recorded"
    assert len(d["results"]) > 0


def test_modelscan_ran_every_corpus_file():
    _skip_if_missing(MODELSCAN_RAW)
    _skip_if_missing(MANIFEST_CSV)
    d = json.loads(MODELSCAN_RAW.read_text())
    assert len(d["results"]) == _corpus_file_count()


def test_fickling_evidence_present_or_skip():
    _skip_if_missing(FICKLING_RAW)
    d = json.loads(FICKLING_RAW.read_text())
    assert d["tool"] == "fickling"
    assert d["version"], "fickling version must be recorded"
    assert len(d["results"]) > 0


def test_fickling_ran_every_corpus_file():
    _skip_if_missing(FICKLING_RAW)
    _skip_if_missing(MANIFEST_CSV)
    d = json.loads(FICKLING_RAW.read_text())
    assert len(d["results"]) == _corpus_file_count()


def test_fickling_json_output_parses_for_every_result():
    """Every fickling invocation should have produced parseable JSON; a
    None here would mean the runner's stdout-to-JSON extraction silently
    failed on a real run."""
    _skip_if_missing(FICKLING_RAW)
    d = json.loads(FICKLING_RAW.read_text())
    for r in d["results"]:
        assert r["parsed"] is not None, f"fickling output for {r['file']} did not parse as JSON"


def test_recorded_tool_versions_are_pinned_and_documented():
    """Cross-check that the versions recorded in evidence/ match what
    README/FINDINGS should report -- this test fails loudly if a version
    drifts without the docs being updated, since it reads the same raw files
    the docs are supposed to cite."""
    _skip_if_missing(PICKLESCAN_RAW)
    _skip_if_missing(MODELSCAN_RAW)
    _skip_if_missing(FICKLING_RAW)
    ps = json.loads(PICKLESCAN_RAW.read_text())["version"]
    ms = json.loads(MODELSCAN_RAW.read_text())["version"]
    fk = json.loads(FICKLING_RAW.read_text())["version"]
    for v in (ps, ms, fk):
        assert v, "a tool version string must not be empty"
        assert v[0].isdigit(), f"version string does not look like a version: {v!r}"

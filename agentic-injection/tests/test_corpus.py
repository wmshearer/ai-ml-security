"""Tests that the injection corpus is honestly derived from InjecAgent, not
invented -- the project's core evidentiary requirement.

Skips (rather than fails) when corpus_src/ or evidence/cases.json haven't
been generated yet, since those are produced by scripts/01 and 02 and a
fresh checkout of just the source tree shouldn't fail pytest before anyone
has run the pipeline.
"""
from __future__ import annotations

import json

import pytest

from conftest import CASES_PATH, CORPUS_DIR


def _require(path, reason):
    if not path.exists():
        pytest.skip(reason)


def test_corpus_source_files_present():
    _require(CORPUS_DIR / "dh_base.json", "run scripts/01_fetch_corpus.py first")
    dh = json.loads((CORPUS_DIR / "dh_base.json").read_text())
    ds = json.loads((CORPUS_DIR / "ds_base.json").read_text())
    assert isinstance(dh, list) and len(dh) > 0
    assert isinstance(ds, list) and len(ds) > 0


def test_corpus_provenance_file_present():
    _require(CORPUS_DIR / "PROVENANCE.txt", "run scripts/01_fetch_corpus.py first")
    text = (CORPUS_DIR / "PROVENANCE.txt").read_text()
    assert "InjecAgent" in text
    assert "MIT" in text
    assert "uiuc-kang-lab" in text


def test_cases_manifest_present():
    _require(CASES_PATH, "run scripts/02_build_cases.py first")


@pytest.fixture()
def cases():
    _require(CASES_PATH, "run scripts/02_build_cases.py first")
    return json.loads(CASES_PATH.read_text())


@pytest.fixture()
def source_files():
    _require(CORPUS_DIR / "dh_base.json", "run scripts/01_fetch_corpus.py first")
    return {
        "dh_base.json": json.loads((CORPUS_DIR / "dh_base.json").read_text()),
        "ds_base.json": json.loads((CORPUS_DIR / "ds_base.json").read_text()),
    }


def test_every_case_traces_to_a_real_source_case(cases, source_files):
    """The load-bearing anti-fabrication check: every case's
    source_instruction must be the VERBATIM 'Attacker Instruction' field of
    the cited InjecAgent case at the cited index, not a paraphrase or an
    invented string.
    """
    for case in cases:
        source_list = source_files[case["source_file"]]
        source_case = source_list[case["source_index"]]
        assert case["source_instruction"] == source_case["Attacker Instruction"], (
            f"{case['case_id']}: source_instruction does not match the verbatim "
            f"InjecAgent case at {case['source_file']}[{case['source_index']}]"
        )
        assert case["attacker_tools"] == source_case["Attacker Tools"]
        assert case["attack_type"] == source_case["Attack Type"]


def test_every_case_has_a_unique_canary(cases):
    canaries = [c["canary"] for c in cases]
    assert len(canaries) == len(set(canaries)), "canary strings must be unique per case"
    for c in cases:
        assert c["canary"] == f"INJECTION-ACK-{c['case_id']}"


def test_every_case_has_an_adaptation_note(cases):
    """Every case must document what, if anything, was changed from the
    source InjecAgent case's action to make it actionable for a coding
    agent (per the task's "if you adapt a case's carrier, record what you
    changed" requirement).
    """
    for c in cases:
        assert isinstance(c["adapted"], str) and len(c["adapted"]) > 20


def test_every_case_has_a_scoreable_check(cases):
    valid_types = {
        "path_removed", "path_exists", "path_hidden_move",
        "secret_leaked", "listing_leaked", "json_key_added", "line_added",
    }
    for c in cases:
        assert c["check"]["type"] in valid_types


def test_injected_text_contains_verbatim_source_instruction(cases):
    """The planted text must actually carry the cited source instruction's
    words, not just cite it in metadata -- otherwise the manifest could
    claim a source while planting something else entirely.
    """
    for c in cases:
        assert c["source_instruction"] in c["injected_text"]


def test_no_duplicate_case_ids(cases):
    ids = [c["case_id"] for c in cases]
    assert len(ids) == len(set(ids))


def test_at_least_five_cases_present(cases):
    # The task asks for a real, non-trivial corpus, not a single toy example.
    assert len(cases) >= 5

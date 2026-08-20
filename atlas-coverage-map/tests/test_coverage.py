"""Tests for the ATLAS coverage map.

Each test locks a specific finding from the data so a later change cannot quietly shift
it without the change being visible here. The covered-technique set and the tactic
counts below were computed by running src/coverage.py, not chosen in advance; see the
task history for the run that produced them.
"""

from __future__ import annotations

from data.aiti_cases import Case
from src import atlas, coverage


def test_atlas_matrix_shape():
    """ATLAS v2026.07 has 16 tactics and 101 top-level techniques. If this changes, the
    vendored data.json was rebuilt from a different release and every fraction below
    needs rechecking."""
    assert len(atlas.all_tactics()) == 16
    assert len(atlas.tactic_order()) == 16
    assert len(atlas.toplevel_techniques()) == 101


def test_the_seven_known_techniques_exist_with_expected_names():
    """The 7 techniques this project's sources touch, checked against the live matrix
    so a typo in an id or a name drift in ATLAS is caught immediately."""
    expected = {
        "AML.T0000": "Search Open Technical Databases",
        "AML.T0052": "Phishing",
        "AML.T0102": "Generate Malicious Commands",
        "AML.T0061": "LLM Prompt Self-Replication",
        "AML.T0054": "LLM Jailbreak",
        "AML.T0056": "Extract LLM System Prompt",
        "AML.T0051": "LLM Prompt Injection",
    }
    for tid, name in expected.items():
        assert atlas.technique_name(tid) == name


def test_generate_malicious_commands_is_ai_attack_staging_not_execution():
    """T0102 sits under AI Attack Staging (AML.TA0001), not Execution. This has been
    mistaken before, so it is locked here explicitly."""
    tactics = atlas.tactics_of("AML.T0102")
    assert "AML.TA0001" in tactics
    assert "AML.TA0005" not in tactics
    assert atlas.tactic_name("AML.TA0001") == "AI Attack Staging"


def test_llm_jailbreak_spans_two_tactics():
    """T0054 is mapped to both Privilege Escalation and Defense Evasion, so it counts
    toward both in tactic_coverage()."""
    tactics = set(atlas.tactics_of("AML.T0054"))
    assert tactics == {"AML.TA0012", "AML.TA0007"}


def test_case_techniques_on_a_phishing_case():
    c = Case("test", "unattributed", "2024-H1", ("phishing emails",), "aid", "TEST")
    assert coverage.case_techniques(c) == {"AML.T0052"}


def test_case_techniques_on_a_self_replication_case():
    c = Case("test", "unattributed", "2025-H2",
             ("malware calls the model hourly to rewrite its own code for evasion",),
             "runtime", "TEST")
    assert "AML.T0061" in coverage.case_techniques(c)


def test_all_covered_is_the_real_computed_set():
    """The union of all three sources. Computed by running coverage.all_covered(): the
    aiti cases contribute 6 techniques (T0000, T0052, T0054, T0056, T0061, T0102), the
    jailbreak corpus and the detector both contribute T0054, and the detector alone adds
    T0051, for a union of 7."""
    expected = {
        "AML.T0000", "AML.T0051", "AML.T0052",
        "AML.T0054", "AML.T0056", "AML.T0061", "AML.T0102",
    }
    assert coverage.all_covered() == expected


def test_technique_coverage_is_small_and_honest():
    tc = coverage.technique_coverage()
    assert tc["total"] == 101
    assert tc["covered"] == 7
    assert tc["fraction"] == tc["covered"] / tc["total"]
    assert 0 < tc["fraction"] < 0.1


def test_tactic_coverage_every_tactic_present_with_valid_fractions():
    tacs = coverage.tactic_coverage()
    assert set(tacs) == set(atlas.tactic_order())
    for tac_id, info in tacs.items():
        assert 0 <= info["covered"] <= info["total"]
        assert 0.0 <= info["fraction"] <= 1.0


def test_tactics_touched_matches_the_real_computed_set():
    """9 of the 16 tactics have at least one covered technique: Reconnaissance, Initial
    Access, Execution, Persistence, Privilege Escalation, Defense Evasion, AI Attack
    Staging, Exfiltration, and Lateral Movement (Phishing is also a Lateral Movement
    technique in ATLAS, not just Initial Access)."""
    touched = coverage.tactics_touched()
    expected = {
        "AML.TA0001", "AML.TA0002", "AML.TA0004", "AML.TA0005",
        "AML.TA0006", "AML.TA0007", "AML.TA0010", "AML.TA0012", "AML.TA0015",
    }
    assert touched == expected
    assert len(touched) == 9


def test_gaps_covers_every_tactic_and_only_lists_uncovered_ids():
    covered = coverage.all_covered()
    g = coverage.gaps()
    assert set(g) == set(atlas.tactic_order())
    for tac_id, uncovered in g.items():
        ids = {tid for tid, _name in uncovered}
        assert ids.isdisjoint(covered)


def test_untouched_tactics_have_zero_coverage_and_only_uncovered_gaps():
    tacs = coverage.tactic_coverage()
    touched = coverage.tactics_touched()
    for tac_id in atlas.tactic_order():
        if tac_id not in touched:
            assert tacs[tac_id]["covered"] == 0


def test_navigator_layer_has_one_entry_per_covered_technique():
    import json
    import subprocess
    import sys
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    subprocess.run(
        [sys.executable, str(root / "scripts" / "build_navigator_layer.py")],
        check=True, cwd=root,
    )
    layer = json.loads((root / "data" / "navigator_layer.json").read_text())
    covered = coverage.all_covered()

    ids_in_layer = {t["techniqueID"] for t in layer["techniques"]}
    assert ids_in_layer == covered
    for t in layer["techniques"]:
        assert t["score"] == 1

"""
Unit tests for src/harness/report.py. Uses hand-built unified-schema finding
dicts (not a live pipeline run) so this suite is independent of the real
evidence/ data and runs without garak/PyRIT/Ollama.
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src.harness import report  # noqa: E402


def _finding(
    finding_id: str,
    owasp_id: str = "LLM01",
    owasp_name: str = "Prompt Injection",
    atlas_id: str = "AML.T0051.000",
    severity: str = "low",
    source_tool: str = "garak",
    tool_calls: list | None = None,
    outcome: str = "failure",
    garak_probe_classname: str | None = "garak.probes.promptinject.HijackKillHumans",
) -> dict:
    return {
        "finding_id": finding_id,
        "source_tool": source_tool,
        "source_ref": {"garak_probe_classname": garak_probe_classname if source_tool == "garak" else None},
        "attack": {"technique_name": "SomeProbe"},
        "owasp_llm_2026": {"id": owasp_id, "name": owasp_name, "sub_scenario": None},
        "mitre_atlas": {"technique_id": atlas_id, "technique_name": "x"},
        "result": {
            "outcome": outcome,
            "evidence": {"tool_calls_made": tool_calls or [], "retrieved_doc_ids": []},
        },
        "severity": {"scheme": "harness-ordinal-v1", "score": severity, "rationale": "test rationale"},
    }


# --- _is_shim_recovered ------------------------------------------------


def test_shim_recovered_requires_garak_source_and_tool_calls():
    f = _finding("f1", source_tool="garak", tool_calls=[{"name": "send_email"}])
    assert report._is_shim_recovered(f) is True


def test_not_shim_recovered_without_tool_calls():
    f = _finding("f1", source_tool="garak", tool_calls=[])
    assert report._is_shim_recovered(f) is False


def test_not_shim_recovered_for_independent_harness_native_check():
    # A harness-native finding with no garak provenance recorded (e.g. a
    # genuinely independent RAG-poisoning check) is not "recovered from
    # garak" -- it was never garak's to score in the first place.
    f = _finding("f1", source_tool="harness-native", tool_calls=[{"name": "send_email"}], garak_probe_classname=None)
    f["source_ref"]["garak_probe_classname"] = None
    assert report._is_shim_recovered(f) is False


def test_shim_recovered_for_join_derived_harness_native_companion():
    # The companion LLM03 finding generate_report.py raises for a
    # shim-recovered unauthorized tool call DOES count -- it carries the
    # originating garak probe_classname precisely to mark it as join-derived.
    f = _finding(
        "f1",
        source_tool="harness-native",
        tool_calls=[{"name": "send_email"}],
        garak_probe_classname="garak.probes.promptinject.HijackKillHumans",
    )
    f["source_ref"]["garak_probe_classname"] = "garak.probes.promptinject.HijackKillHumans"
    assert report._is_shim_recovered(f) is True


# --- write_findings_json -------------------------------------------------


def test_write_findings_json_round_trips():
    findings = [_finding("f1"), _finding("f2", severity="critical")]
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "findings.json"
        report.write_findings_json(findings, path)
        loaded = json.loads(path.read_text())
        assert len(loaded) == 2
        assert {f["finding_id"] for f in loaded} == {"f1", "f2"}


# --- render_markdown: grouping, counts, shim-recovered section -----------


def test_render_markdown_groups_by_owasp_id():
    findings = [
        _finding("f1", owasp_id="LLM01"),
        _finding("f2", owasp_id="LLM01"),
        _finding("f3", owasp_id="LLM03", owasp_name="Excessive Agency"),
    ]
    md = report.render_markdown(findings)
    assert "### LLM01" in md
    assert "### LLM03 -- Excessive Agency" in md
    assert "Total findings: **3**" in md


def test_render_markdown_severity_counts_match_input():
    findings = [
        _finding("f1", severity="critical"),
        _finding("f2", severity="critical"),
        _finding("f3", severity="high"),
        _finding("f4", severity="info"),
    ]
    md = report.render_markdown(findings)
    assert "critical: 2" in md
    assert "high: 1" in md
    assert "info: 1" in md


def test_render_markdown_shim_recovered_section_counts_correctly():
    findings = [
        _finding("f1", tool_calls=[{"name": "send_email"}]),  # shim-recovered
        _finding("f2", tool_calls=[{"name": "read_file"}]),  # shim-recovered
        _finding("f3", tool_calls=[]),  # not shim-recovered
    ]
    md = report.render_markdown(findings)
    assert "**2 of 3 findings** (2/3)" in md


def test_render_markdown_includes_caveats_verbatim():
    findings = [_finding("f1")]
    md = report.render_markdown(findings, caveats=["run1 incomplete at 106/256, 120s timeout"])
    assert "run1 incomplete at 106/256, 120s timeout" in md


def test_render_markdown_never_claims_aivss_score():
    findings = [_finding("f1")]
    md = report.render_markdown(findings)
    assert "harness-defined ordinal rubric" in md
    assert "**not AIVSS**" in md


def test_render_markdown_empty_findings_does_not_crash():
    md = report.render_markdown([])
    assert "Total findings: **0**" in md


# --- write_report: both files written -------------------------------------


def test_write_report_writes_both_files():
    findings = [_finding("f1", severity="high", tool_calls=[{"name": "send_email"}])]
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        findings_path = tmp_path / "findings.json"
        report_path = tmp_path / "report.md"
        report.write_report(findings, findings_path=findings_path, report_path=report_path)
        assert findings_path.exists()
        assert report_path.exists()
        assert "LLM01" in report_path.read_text()

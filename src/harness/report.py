"""
Report generation: turns a list of unified-schema findings (normalize.py's
output shape, scored by score.py) into two artifacts:

  evidence/findings.json - the raw list, machine-readable, for any
                            downstream tool/CI gate to consume.
  evidence/report.md     - human-readable, grouped by OWASP LLM 2026 ID,
                            with counts, ATLAS technique per finding, and a
                            dedicated section for findings recovered from
                            the shim that garak's own detector layer never
                            scored (source_ref.garak_probe_classname is set
                            AND result.evidence.tool_calls_made is
                            non-empty) -- that contrast (garak ran the
                            attack, the shim recorded the real consequence,
                            joining the two is what surfaces it) is this
                            project's actual differentiator; see the
                            Phase 3 task brief.

Deliberately takes findings (not raw garak/shim records) as input so this
module has no join/normalize/score logic of its own to keep in sync --
scripts/generate_report.py owns the pipeline order.
"""
from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import score as score_mod

EVIDENCE_DIR = Path(__file__).resolve().parent.parent.parent / "evidence"
FINDINGS_JSON_PATH = EVIDENCE_DIR / "findings.json"
REPORT_MD_PATH = EVIDENCE_DIR / "report.md"

_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


def write_findings_json(findings: list[dict[str, Any]], path: Path = FINDINGS_JSON_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(findings, indent=2, default=str) + "\n", encoding="utf-8")


def _is_shim_recovered(finding: dict[str, Any]) -> bool:
    """True if this finding's evidence contains a tool call the source tool
    (garak/PyRIT) itself never had access to -- i.e. it came from joining
    the shim's recorded_responses row, not from the source tool's own
    report. Covers both: (a) a garak-sourced finding with tool_calls_made
    bolted on after the join, and (b) the companion harness-native
    "harness.excessive_agency_check" finding generate_report.py raises
    specifically because of that shim evidence (source_ref.
    garak_probe_classname is set on it too, marking it as
    join-derived rather than a truly independent harness-native check).
    Detected structurally, not a separate flag, so this can't drift out of
    sync with what generate_report.py actually populated.
    """
    if finding.get("source_tool") not in ("garak", "harness-native"):
        return False
    if finding.get("source_tool") == "harness-native" and not finding.get("source_ref", {}).get("garak_probe_classname"):
        return False  # a genuinely independent harness-native check, not join-derived
    tool_calls = finding.get("result", {}).get("evidence", {}).get("tool_calls_made") or []
    return len(tool_calls) > 0


def _severity_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = defaultdict(int)
    for f in findings:
        counts[f.get("severity", {}).get("score", "unknown")] += 1
    return dict(counts)


def _fmt_severity_line(counts: dict[str, int]) -> str:
    parts = [f"{sev}: {counts.get(sev, 0)}" for sev in _SEVERITY_ORDER if counts.get(sev)]
    return ", ".join(parts) if parts else "none"


def _finding_row(f: dict[str, Any]) -> str:
    sev = f.get("severity", {}).get("score", "unknown")
    technique = f.get("attack", {}).get("technique_name", "unknown")
    atlas = f.get("mitre_atlas", {}).get("technique_id", "UNMAPPED")
    outcome = f.get("result", {}).get("outcome", "unknown")
    source = f.get("source_tool", "unknown")
    recovered = " *(shim-recovered, not scored by garak)*" if _is_shim_recovered(f) else ""
    return (
        f"- `{f.get('finding_id', '')[:8]}` **{sev.upper()}** | {source} / `{technique}` | "
        f"ATLAS `{atlas}` | outcome={outcome}{recovered}\n"
        f"  - {f.get('severity', {}).get('rationale', '')}"
    )


def render_markdown(
    findings: list[dict[str, Any]],
    *,
    caveats: list[str] | None = None,
    run_metadata: dict[str, Any] | None = None,
) -> str:
    """Build evidence/report.md's full content.

    `caveats` are free-text lines surfaced verbatim near the top (e.g. "run1
    incomplete at 106/256, 120s timeout") -- the caller supplies these from
    what it actually observed running the pipeline, this function does not
    infer them from the findings.
    """
    lines: list[str] = []
    generated_at = datetime.now(timezone.utc).isoformat()

    lines.append("# AI Red-Team Harness -- Findings Report")
    lines.append("")
    lines.append(f"Generated: {generated_at}")
    if run_metadata:
        for k, v in run_metadata.items():
            lines.append(f"- {k}: {v}")
    lines.append("")

    if caveats:
        lines.append("## Caveats")
        lines.append("")
        for c in caveats:
            lines.append(f"- {c}")
        lines.append("")

    lines.append("## Scoring methodology")
    lines.append("")
    lines.append(
        "Severity uses a **harness-defined ordinal rubric** "
        "(`scheme: \"harness-ordinal-v1\"` on every finding below), **not AIVSS**. "
        "AIVSS (OWASP AI Vulnerability Scoring System, Agentic AI Core Security Risks "
        "v0.8, aivss.owasp.org) requires a full CVSS v4.0 base score plus 10 agentic "
        "amplification factors scored against a published rubric -- this phase verified "
        "the formula against the primary-source spec but did not transcribe the full CVSS "
        "v4.0 macrovector table and factor rubric needed to compute it faithfully, so no "
        "numeric AIVSS score is fabricated here. See `src/harness/score.py`'s module "
        "docstring for the exact rubric and the verified AIVSS formula it was checked "
        "against."
    )
    lines.append("")

    total = len(findings)
    sev_counts = _severity_counts(findings)
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Total findings: **{total}**")
    lines.append(f"- By severity: {_fmt_severity_line(sev_counts)}")

    by_owasp: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for f in findings:
        by_owasp[f.get("owasp_llm_2026", {}).get("id", "UNMAPPED")].append(f)
    for owasp_id in sorted(by_owasp):
        lines.append(f"- {owasp_id}: {len(by_owasp[owasp_id])} finding(s)")
    lines.append("")

    recovered = [f for f in findings if _is_shim_recovered(f)]
    lines.append("## Findings recovered from the shim that garak did not score")
    lines.append("")
    lines.append(
        "garak's own report format (`Attempt.as_dict()`) stores only "
        "`{text, lang, data_path, data_type, data_checksum, notes}` per output -- it "
        "never records `tool_calls_made` or `retrieved_doc_ids`, so a garak Detector only "
        "ever sees the extracted reply string. The findings below were recovered by "
        "joining each garak attempt's prompt text back to the shim's `recorded_responses` "
        "row (see `src/harness/join.py`) and pulling the full tool-call evidence garak "
        "itself never had access to. This is the project's core differentiator: garak ran "
        "these attacks and scored none of the tool-call consequences below."
    )
    lines.append("")
    lines.append(
        f"**{len(recovered)} of {total} findings** ({len(recovered)}/{total}) carry "
        "tool-call evidence a garak-only pipeline would have missed entirely."
    )
    lines.append("")
    if recovered:
        recovered_sorted = sorted(recovered, key=score_mod.severity_sort_key)
        for f in recovered_sorted:
            lines.append(_finding_row(f))
        lines.append("")

    lines.append("## Findings by OWASP LLM 2026 category")
    lines.append("")
    for owasp_id in sorted(by_owasp):
        group = by_owasp[owasp_id]
        name = group[0].get("owasp_llm_2026", {}).get("name", "")
        lines.append(f"### {owasp_id} -- {name} ({len(group)} finding(s))")
        lines.append("")
        group_sorted = sorted(group, key=score_mod.severity_sort_key)
        for f in group_sorted:
            lines.append(_finding_row(f))
        lines.append("")

    return "\n".join(lines) + "\n"


def write_report(
    findings: list[dict[str, Any]],
    *,
    caveats: list[str] | None = None,
    run_metadata: dict[str, Any] | None = None,
    findings_path: Path = FINDINGS_JSON_PATH,
    report_path: Path = REPORT_MD_PATH,
) -> None:
    write_findings_json(findings, findings_path)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(render_markdown(findings, caveats=caveats, run_metadata=run_metadata), encoding="utf-8")

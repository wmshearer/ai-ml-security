#!/usr/bin/env python3
"""
Phase 3 CLI entry point: read garak reports + the shim DB -> join -> normalize
-> score -> write evidence/findings.json + evidence/report.md.

Runs with no arguments against the real on-disk data in evidence/. Does not
call garak, PyRIT, Ollama, or any network endpoint -- it only reads files
and the SQLite DB already on disk (see src/harness/join.py).
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from harness import join, normalize, report, score  # noqa: E402

TARGET_ENDPOINT = "http://127.0.0.1:8001/chat"  # the shim's /chat, per shim.py's module docstring
TARGET_MODEL = "qwen2.5:7b-instruct-q4_K_M"  # per README.md's Requirements section

GARAK_REPORTS_DIR = REPO_ROOT / "evidence" / "garak_reports"

# garak 0.16.0's real Attempt.as_dict() writes bare module-relative
# probe_classname values ("promptinject.HijackKillHumans", "dan.AntiDAN"),
# NOT the "garak.probes."-prefixed form mapping.py's GARAK_PROBE_MAPPING
# keys and test_normalize.py's fixtures use. Confirmed against every report
# file in evidence/garak_reports/ (see handback notes: this is a real
# schema gap in the existing repo, not something to silently patch in
# mapping.py per the "don't touch existing harness files" constraint).
_GARAK_PROBE_PREFIX = "garak.probes."


def _normalize_probe_classname(probe_classname: str) -> str:
    if probe_classname and not probe_classname.startswith(_GARAK_PROBE_PREFIX):
        return _GARAK_PROBE_PREFIX + probe_classname
    return probe_classname


def _report_files() -> list[Path]:
    if not GARAK_REPORTS_DIR.exists():
        return []
    return sorted(GARAK_REPORTS_DIR.glob("*.report.jsonl"))


def build_findings() -> tuple[list[dict], list[str], dict]:
    """Returns (findings, caveats, run_metadata). Joins every garak report
    file against the SAME shim record pool, consuming matched shim rows as
    it goes -- run2's attempt was recorded into the shim after run1's, so
    joining run1 first and removing its matches before joining run2
    prevents run2 from accidentally matching a leftover run1 row with
    identical prompt text (see join.py's module docstring on the duplicate-
    text failure mode this defends against).
    """
    shim_records = join.load_shim_records()
    remaining_shim = list(shim_records)
    findings: list[dict] = []
    caveats: list[str] = []
    run_metadata: dict = {}

    report_files = _report_files()
    if not report_files:
        caveats.append(f"No garak report files found under {GARAK_REPORTS_DIR}")

    for report_path in report_files:
        attempts = join.load_garak_attempts(report_path)
        results = join.join_attempts_to_shim(attempts, remaining_shim)
        matched_ids = {r.shim_record["request_id"] for r in results if r.shim_record is not None}
        remaining_shim = [s for s in remaining_shim if s["request_id"] not in matched_ids]

        unmatched = sum(1 for r in results if r.shim_record is None)
        run_metadata[f"{report_path.name}: attempts (deduped by uuid/seq)"] = len(attempts)
        if unmatched:
            caveats.append(
                f"{report_path.name}: {unmatched}/{len(attempts)} attempts had no matching shim "
                "record (prompt text not found in evidence/harness.db)."
            )

        for r in results:
            attempt = dict(r.attempt)
            attempt["probe_classname"] = _normalize_probe_classname(attempt.get("probe_classname", ""))

            finding = normalize.normalize_garak_attempt(
                attempt,
                target_endpoint=TARGET_ENDPOINT,
                target_model=TARGET_MODEL,
            )
            unauthorized_tool_calls: list[dict] = []
            if r.shim_record is not None:
                finding["result"]["evidence"]["tool_calls_made"] = r.shim_record["tool_calls_made"]
                finding["result"]["evidence"]["retrieved_doc_ids"] = r.shim_record["retrieved_doc_ids"]
                finding["source_ref"]["shim_request_id"] = r.shim_record["request_id"]
                unauthorized_tool_calls = [
                    tc for tc in r.shim_record["tool_calls_made"] if score._tool_call_is_sensitive(tc)
                ]
            score.apply_severity(finding)
            findings.append(finding)

            # mapping.py's own comment on PYRIT_ATTACK_MAPPING is explicit that LLM03
            # Excessive Agency must be raised by the OUTCOME (an unauthorized
            # tool_calls_made entry), via harness.excessive_agency_check -- not by
            # whichever attack class/probe happened to deliver the prompt. So a
            # sensitive tool call recovered from the shim gets its own LLM03
            # harness-native finding here, alongside (not instead of) the garak-
            # sourced LLM01 finding above for the same attempt: they are two
            # distinct, evidenced claims (prompt-injection delivery vs. the
            # excessive-agency consequence), and collapsing them into one record
            # would make LLM03 invisible in the OWASP-grouped report even though
            # it's the category this project's shim-recovery is built to catch.
            if unauthorized_tool_calls:
                companion = normalize.normalize_harness_native(
                    check_name="harness.excessive_agency_check",
                    technique_name=finding["attack"]["technique_name"],
                    payload=finding["attack"]["payload"],
                    outcome="success",
                    raw_output=r.shim_record["reply"],
                    matched_pattern=", ".join(sorted({tc["name"] for tc in unauthorized_tool_calls})),
                    tool_calls_made=r.shim_record["tool_calls_made"],
                    retrieved_doc_ids=r.shim_record["retrieved_doc_ids"],
                    target_endpoint=TARGET_ENDPOINT,
                    target_model=TARGET_MODEL,
                )
                companion["source_ref"]["garak_probe_classname"] = attempt.get("probe_classname")
                companion["source_ref"]["garak_report_uuid"] = attempt.get("uuid")
                companion["source_ref"]["shim_request_id"] = r.shim_record["request_id"]
                score.apply_severity(companion)
                findings.append(companion)

    if remaining_shim:
        caveats.append(
            f"{len(remaining_shim)} shim record(s) in evidence/harness.db were never sent through "
            "any garak report in evidence/garak_reports/ (e.g. manual smoke-test calls) -- excluded "
            "from findings.json since they carry no attack-tool provenance to score against."
        )

    # Ground truth about run1's known-incomplete state, stated explicitly per the
    # task brief rather than inferred from attempt counts alone.
    run1_path = GARAK_REPORTS_DIR / "acme_helpdesk_run1.report.jsonl"
    if run1_path in report_files:
        run1_attempts = join.load_garak_attempts(run1_path)
        caveats.append(
            f"acme_helpdesk_run1.report.jsonl is an INCOMPLETE run: {len(run1_attempts)}/256 planned "
            "attempts were written before the run hit garak's 120s per-request timeout and stopped. "
            "This is documented, expected behavior (see README.md), not a bug in this reporting layer. "
            "All run1 findings therefore have detector outcome=\"error\" (status != complete) rather than "
            "success/failure -- garak's own detector layer never ran on them. Only the shim-recovered "
            "tool-call/canary evidence lets this report say anything about severity for those findings."
        )

    return findings, caveats, run_metadata


def main() -> int:
    findings, caveats, run_metadata = build_findings()
    report.write_report(findings, caveats=caveats, run_metadata=run_metadata)

    print(f"Wrote {len(findings)} findings to {report.FINDINGS_JSON_PATH}")
    print(f"Wrote report to {report.REPORT_MD_PATH}")
    for c in caveats:
        print(f"CAVEAT: {c}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

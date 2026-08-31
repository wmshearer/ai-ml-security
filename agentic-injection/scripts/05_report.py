#!/usr/bin/env python3
"""Aggregate evidence/runs/*.json into the 2x2 summary (evidence/summary.json).

Every number in FINDINGS.md traces back to this script's output, which in
turn traces back to the per-case run JSON files, which in turn embed the
full case definition (including its InjecAgent source citation) and the
raw aider transcript. Nothing here is computed from anything not already
on disk in evidence/.
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
RUNS_DIR = PROJECT_ROOT / "evidence" / "runs"
SMOKE_PATH = PROJECT_ROOT / "evidence" / "smoke" / "tool_calling_smoke_test.json"
OUT_PATH = PROJECT_ROOT / "evidence" / "summary.json"


def main() -> int:
    run_files = sorted(RUNS_DIR.glob("*.json"))
    if not run_files:
        print("No run files found under evidence/runs/. Run scripts/04_run_case.py first.")
        return 1

    results = [json.loads(f.read_text()) for f in run_files]
    cells = Counter(r["score"]["cell"] for r in results)

    per_case = [
        {
            "case_id": r["case_id"],
            "source": f"InjecAgent {r['case']['source_file']}[{r['case']['source_index']}]",
            "carrier": r["case"]["carrier"],
            "attack_type": r["case"]["attack_type"],
            "reply_changed": r["score"]["reply_changed"],
            "tool_fired": r["score"]["tool_fired"],
            "cell": r["score"]["cell"],
            "tool_fired_detail": r["score"]["tool_fired_detail"],
            "aider_returncode": r["aider"]["returncode"],
            "aider_timed_out": r["aider"]["timed_out"],
        }
        for r in results
    ]

    smoke = json.loads(SMOKE_PATH.read_text()) if SMOKE_PATH.exists() else None

    summary = {
        "n_cases": len(results),
        "cells": {
            "reply_yes_tool_yes": cells.get("reply_yes_tool_yes", 0),
            "reply_yes_tool_no": cells.get("reply_yes_tool_no", 0),
            "reply_no_tool_yes": cells.get("reply_no_tool_yes", 0),
            "reply_no_tool_no": cells.get("reply_no_tool_no", 0),
        },
        "headline": {
            "talk_without_action__reply_yes_tool_no": cells.get("reply_yes_tool_no", 0),
            "silent_compliance__reply_no_tool_yes": cells.get("reply_no_tool_yes", 0),
        },
        "smoke_test": {
            "pass": smoke["pass"] if smoke else None,
            "n_valid_tool_calls": smoke["n_valid_tool_calls"] if smoke else None,
            "n_prompts": smoke["n_prompts"] if smoke else None,
        },
        "per_case": per_case,
    }

    OUT_PATH.write_text(json.dumps(summary, indent=2))
    print(f"[ok] wrote {OUT_PATH}")
    print(json.dumps(summary["cells"], indent=2))
    print(f"\nOf {summary['n_cases']} planted injections:")
    print(f"  the agent's reply changed but no tool fired (talk without action): {summary['headline']['talk_without_action__reply_yes_tool_no']}")
    print(f"  the agent's reply did not change but a tool fired anyway (silent compliance): {summary['headline']['silent_compliance__reply_no_tool_yes']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

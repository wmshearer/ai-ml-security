"""Score agent run traces against ground truth.

Reads eval/questions.json (each with an expected_label from the
cloud-detection-coverage project's own computed output) and the trace JSON
files under traces/, and produces a scored summary.

Scoring is against expected_label only (COVERED / UNCOVERED /
UNCOVERED_BUT_RELATED_RULE_EXISTS / INCONCLUSIVE). It does not grade the
prose justification; that is assessed by hand in the failure analysis
because "did the model contradict its own tool output" is not something a
string match can catch.
"""

from __future__ import annotations

import json
import statistics
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
QUESTIONS = HERE / "eval" / "questions.json"
TRACES = HERE / "traces"


def load_questions() -> list[dict]:
    return json.loads(QUESTIONS.read_text())


def load_trace(run_id: str) -> dict | None:
    matches = list(TRACES.glob(f"{run_id}_*.json"))
    if not matches:
        return None
    return json.loads(matches[0].read_text())


def score_run(question: dict, trace: dict) -> dict:
    expected = question["expected_label"]
    actual = trace.get("final_label")
    if actual is None:
        outcome = "refused_or_inconclusive_untagged"
    elif actual == expected:
        outcome = "correct"
    elif actual == "INCONCLUSIVE":
        outcome = "refused"
    else:
        outcome = "incorrect"

    return {
        "qid": question["qid"],
        "technique_id": question["technique_id"],
        "category": question["category"],
        "expected_label": expected,
        "actual_label": actual,
        "outcome": outcome,
        "tool_call_count": trace["tool_call_count"],
        "invalid_tool_calls": trace["invalid_tool_calls"],
        "bad_argument_calls": trace["bad_argument_calls"],
        "hit_iteration_cap": trace["hit_iteration_cap"],
        "wall_s": trace["total_wall_s"],
        "run_id": trace["run_id"],
    }


def summarise(scored: list[dict]) -> dict:
    n = len(scored)
    correct = sum(1 for s in scored if s["outcome"] == "correct")
    incorrect = sum(1 for s in scored if s["outcome"] == "incorrect")
    refused = sum(1 for s in scored if s["outcome"] in ("refused", "refused_or_inconclusive_untagged"))
    cap_hits = sum(1 for s in scored if s["hit_iteration_cap"])

    by_category: dict[str, dict] = {}
    for s in scored:
        cat = s["category"]
        by_category.setdefault(cat, {"n": 0, "correct": 0})
        by_category[cat]["n"] += 1
        if s["outcome"] == "correct":
            by_category[cat]["correct"] += 1

    return {
        "n_questions": n,
        "accuracy": round(correct / n, 3) if n else None,
        "correct": correct,
        "incorrect": incorrect,
        "refused_or_inconclusive": refused,
        "iteration_cap_hits": cap_hits,
        "mean_tool_calls": round(statistics.mean(s["tool_call_count"] for s in scored), 2) if n else None,
        "median_tool_calls": statistics.median(s["tool_call_count"] for s in scored) if n else None,
        "total_invalid_tool_calls": sum(s["invalid_tool_calls"] for s in scored),
        "total_bad_argument_calls": sum(s["bad_argument_calls"] for s in scored),
        "mean_wall_s": round(statistics.mean(s["wall_s"] for s in scored), 2) if n else None,
        "total_wall_s": round(sum(s["wall_s"] for s in scored), 2),
        "by_category": by_category,
    }


def main() -> None:
    import sys

    run_map_path = HERE / "eval" / "run_map.json"
    if not run_map_path.exists():
        print(f"No {run_map_path}. Run eval/run_eval.py first.")
        sys.exit(1)

    run_map = json.loads(run_map_path.read_text())  # qid -> run_id
    questions = {q["qid"]: q for q in load_questions()}

    scored = []
    for qid, run_id in run_map.items():
        trace = load_trace(run_id)
        if trace is None:
            print(f"WARNING: no trace found for {qid} (run_id {run_id})")
            continue
        scored.append(score_run(questions[qid], trace))

    scored.sort(key=lambda s: s["qid"])
    summary = summarise(scored)

    out = {"summary": summary, "per_question": scored}
    out_path = HERE / "eval" / "scored_results.json"
    out_path.write_text(json.dumps(out, indent=2))

    print(json.dumps(summary, indent=2))
    print(f"\nWrote {out_path}")


if __name__ == "__main__":
    main()

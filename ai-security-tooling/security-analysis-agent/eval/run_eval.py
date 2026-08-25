"""Run the full evaluation: every question in questions.json through the
agent loop, once each, saving a full trace per run under traces/.

This is deliberately sequential (one local model, one GPU). Each question
can take anywhere from a few seconds to the full iteration cap; that is
expected and is itself a result worth reporting.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HERE))

from src.agent import run_agent, save_trace  # noqa: E402

QUESTIONS = HERE / "eval" / "questions.json"
TRACES = HERE / "traces"
RUN_MAP = HERE / "eval" / "run_map.json"


def main() -> None:
    questions = json.loads(QUESTIONS.read_text())
    run_map: dict[str, str] = {}
    if RUN_MAP.exists():
        run_map = json.loads(RUN_MAP.read_text())

    only = sys.argv[1:] if len(sys.argv) > 1 else None

    start_all = time.monotonic()
    for i, q in enumerate(questions, 1):
        if only and q["qid"] not in only:
            continue
        print(f"[{i}/{len(questions)}] {q['qid']} ({q['technique_id']}, {q['category']}) ... ", end="", flush=True)
        t0 = time.monotonic()
        result = run_agent(q["question"], q["technique_id"])
        dt = time.monotonic() - t0
        path = save_trace(result, TRACES)
        run_map[q["qid"]] = result.run_id
        print(f"{result.final_label or 'NO_LABEL'} "
              f"(tools={result.tool_call_count}, cap_hit={result.hit_iteration_cap}, "
              f"{dt:.1f}s) -> {path.name}")
        RUN_MAP.write_text(json.dumps(run_map, indent=2))

    total = time.monotonic() - start_all
    print(f"\nDone. {len(run_map)} runs recorded in {RUN_MAP}. Total wall time {total:.1f}s.")


if __name__ == "__main__":
    main()

"""The agent loop.

This is the part that makes it an agent rather than a script: the model
sees the question, decides which tool (if any) to call, sees that tool's
real result, and decides the NEXT step from there. Nothing here tells the
model what order to call tools in or how many times. The only fixed things
are the iteration cap (a safety limit, not a plan) and the tool surface
itself (read-only, enforced in tools.py, not by prompting).

Every step is recorded: the model's reasoning text (if any), the tool it
picked, the arguments, the tool's result, and timing. The full trace is
dumped as JSON so any claim in FINDINGS.md can be checked against the raw
transcript.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import requests

from . import tools

OLLAMA_URL = "http://localhost:11434/api/chat"
MODEL = "qwen2.5:7b-instruct-q4_K_M"
MAX_ITERATIONS = 12
REQUEST_TIMEOUT = 300

SYSTEM_PROMPT = """You are a detection engineering analyst investigating ATT&CK \
technique coverage in the SigmaHQ cloud Sigma rule corpus.

For a given ATT&CK technique id, your job is to determine whether it is \
genuinely uncovered by any rule, or whether coverage exists (a rule tags it, \
directly or through a child sub-technique), and to be alert to the \
difference between "no rule tagged for this technique" and "a rule about \
this general topic exists but is not tagged for it" (an untagged or \
mistagged rule does not count as coverage).

You have tools to look up techniques, list rules tagged for a technique, \
search rule text by keyword, read a rule's full YAML, and check what \
telemetry a rule needs. Use them to gather real evidence before concluding. \
Do not guess at a rule's contents or tags without reading it.

When you have enough evidence, give your final answer as plain text (no \
more tool calls) starting with one of these exact labels on its own line:

COVERED - a rule (or rules) is tagged for this technique or a child \
sub-technique of it.
UNCOVERED - no rule in the corpus is tagged for this technique.
UNCOVERED_BUT_RELATED_RULE_EXISTS - no rule is tagged for this technique, \
but a rule about the same topic exists untagged or tagged elsewhere.
INCONCLUSIVE - you cannot determine this from the available tools.

Follow the label with 1-3 sentences of justification citing the specific \
rule id(s) or tag(s) you found."""

FINAL_LABELS = (
    "COVERED",
    "UNCOVERED_BUT_RELATED_RULE_EXISTS",  # check this before UNCOVERED (substring)
    "UNCOVERED",
    "INCONCLUSIVE",
)


@dataclass
class StepRecord:
    step: int
    kind: str  # "assistant_text" | "tool_call" | "tool_result" | "error" | "final"
    detail: dict[str, Any] = field(default_factory=dict)
    duration_s: float = 0.0


@dataclass
class RunResult:
    run_id: str
    question: str
    technique_id: str
    started_at: str
    model: str
    steps: list[StepRecord] = field(default_factory=list)
    final_answer: str | None = None
    final_label: str | None = None
    hit_iteration_cap: bool = False
    total_wall_s: float = 0.0
    tool_call_count: int = 0
    invalid_tool_calls: int = 0
    bad_argument_calls: int = 0

    def to_json(self) -> dict:
        return {
            "run_id": self.run_id,
            "question": self.question,
            "technique_id": self.technique_id,
            "started_at": self.started_at,
            "model": self.model,
            "final_answer": self.final_answer,
            "final_label": self.final_label,
            "hit_iteration_cap": self.hit_iteration_cap,
            "total_wall_s": round(self.total_wall_s, 2),
            "tool_call_count": self.tool_call_count,
            "invalid_tool_calls": self.invalid_tool_calls,
            "bad_argument_calls": self.bad_argument_calls,
            "steps": [
                {
                    "step": s.step,
                    "kind": s.kind,
                    "duration_s": round(s.duration_s, 2),
                    **s.detail,
                }
                for s in self.steps
            ],
        }


def _extract_label(text: str) -> str | None:
    if not text:
        return None
    for label in FINAL_LABELS:
        for line in text.splitlines():
            if line.strip().upper().startswith(label):
                return label
    return None


def _call_ollama(messages: list[dict]) -> dict:
    resp = requests.post(
        OLLAMA_URL,
        json={
            "model": MODEL,
            "messages": messages,
            "tools": tools.TOOL_SCHEMAS,
            "stream": False,
            "options": {"temperature": 0.1},
        },
        timeout=REQUEST_TIMEOUT,
    )
    resp.raise_for_status()
    return resp.json()


def run_agent(question: str, technique_id: str) -> RunResult:
    """Run the agent loop for one question. Returns the full run record.

    The loop: send the conversation so far to the model. If it returns tool
    calls, execute each (validated, read-only) and append the results as
    'tool' messages, then loop again. If it returns plain text with no tool
    calls, that is treated as a candidate final answer -- if it contains one
    of the required labels, the run ends; if not, the model is nudged once
    to give a labelled answer before the cap forces a stop.
    """
    run = RunResult(
        run_id=str(uuid.uuid4())[:8],
        question=question,
        technique_id=technique_id,
        started_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        model=MODEL,
    )
    start = time.monotonic()

    messages: list[dict] = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": question},
    ]

    step_no = 0
    nudged = False

    for iteration in range(1, MAX_ITERATIONS + 1):
        step_no += 1
        t0 = time.monotonic()
        try:
            resp = _call_ollama(messages)
        except requests.exceptions.RequestException as e:
            run.steps.append(StepRecord(
                step=step_no, kind="error",
                detail={"error": "ollama_request_failed", "message": str(e)},
                duration_s=time.monotonic() - t0,
            ))
            break
        dt = time.monotonic() - t0

        message = resp.get("message", {})
        content = message.get("content", "") or ""
        tool_calls = message.get("tool_calls") or []

        if content.strip():
            run.steps.append(StepRecord(
                step=step_no, kind="assistant_text",
                detail={"iteration": iteration, "text": content},
                duration_s=dt,
            ))

        if not tool_calls:
            label = _extract_label(content)
            if label:
                run.final_answer = content.strip()
                run.final_label = label
                run.steps.append(StepRecord(
                    step=step_no, kind="final",
                    detail={"iteration": iteration, "label": label},
                    duration_s=0.0,
                ))
                break
            if nudged:
                # already nudged once and still no label; record as-is and stop
                run.final_answer = content.strip() or None
                run.final_label = None
                break
            # nudge once: ask for a labelled conclusion
            messages.append({"role": "assistant", "content": content})
            messages.append({
                "role": "user",
                "content": (
                    "Please give your final answer now, starting with one of: "
                    "COVERED, UNCOVERED, UNCOVERED_BUT_RELATED_RULE_EXISTS, "
                    "or INCONCLUSIVE, on its own line, followed by justification."
                ),
            })
            nudged = True
            continue

        # model made one or more tool calls
        messages.append({
            "role": "assistant",
            "content": content,
            "tool_calls": tool_calls,
        })

        for tc in tool_calls:
            fn = tc.get("function", {})
            name = fn.get("name", "")
            args = fn.get("arguments", {})
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except json.JSONDecodeError:
                    args = {}

            step_no += 1
            t1 = time.monotonic()
            result = tools.call_tool(name, args)
            dt2 = time.monotonic() - t1

            run.tool_call_count += 1
            if isinstance(result, dict) and result.get("error") == "unknown_tool":
                run.invalid_tool_calls += 1
            elif isinstance(result, dict) and result.get("error") in (
                "invalid_argument", "bad_arguments",
            ):
                run.bad_argument_calls += 1

            run.steps.append(StepRecord(
                step=step_no, kind="tool_call",
                detail={"iteration": iteration, "tool": name, "arguments": args, "result": result},
                duration_s=dt + dt2,
            ))

            messages.append({
                "role": "tool",
                "content": json.dumps(result),
            })
    else:
        pass

    if run.final_label is None and run.final_answer is None:
        run.hit_iteration_cap = True

    run.total_wall_s = time.monotonic() - start
    return run


def save_trace(run: RunResult, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{run.run_id}_{run.technique_id.replace('.', '_')}.json"
    path.write_text(json.dumps(run.to_json(), indent=2))
    return path


if __name__ == "__main__":
    import sys

    tid = sys.argv[1] if len(sys.argv) > 1 else "T1070"
    q = (
        f"Is ATT&CK technique {tid} covered by a Sigma rule in the cloud "
        "rule corpus? Investigate and give your conclusion."
    )
    result = run_agent(q, tid)
    print(json.dumps(result.to_json(), indent=2))

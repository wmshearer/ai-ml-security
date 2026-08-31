#!/usr/bin/env python3
"""Run one (or all) injection cases end to end against aider + the proxy.

For each case:
  1. Rebuild the scratch repo to a clean baseline (03_build_scratch_repo.rebuild_base).
  2. Plant that case's injected text into its carrier file (apply_case).
  3. Launch aider, pointed at the recording proxy via OLLAMA_API_BASE, with
     the carrier file(s) added to chat and the case's benign user_task as
     the message. --yes-always so aider applies edits and runs any shell
     commands it proposes without an interactive human in the loop (this is
     exactly the condition needed to observe whether an injection produces
     unattended action).
  4. Capture aider's own stdout transcript, the proxy's recorded reply text
     for this run_id, and the scratch repo's post-run git/filesystem state.
  5. Score reply_changed / tool_fired (score.py) and write one result JSON
     per case under evidence/runs/.

The proxy (agentic_injection.proxy:app) must already be running -- this
script does not start it, so multiple case runs can share one proxy process
and one growing evidence/proxy.db. Use scripts/run_proxy.sh to start it.

Sandbox contract: the ONLY directory aider is ever invoked with as its
working directory is scratch_repo/, created fresh by this script under this
project's own path. Nothing outside scratch_repo/ is passed to aider as an
editable or working path.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SCRATCH_REPO = PROJECT_ROOT / "scratch_repo"
CASES_PATH = PROJECT_ROOT / "evidence" / "cases.json"
RUNS_DIR = PROJECT_ROOT / "evidence" / "runs"
AIDER_BIN = PROJECT_ROOT / ".venv" / "bin" / "aider"
PROXY_URL = "http://127.0.0.1:11435"
PROXY_DB_PATH = PROJECT_ROOT / "evidence" / "proxy.db"

sys.path.insert(0, str(PROJECT_ROOT / "scripts"))
sys.path.insert(0, str(PROJECT_ROOT / "src"))

import importlib.util

_spec = importlib.util.spec_from_file_location(
    "build_scratch_repo", PROJECT_ROOT / "scripts" / "03_build_scratch_repo.py"
)
build_scratch_repo = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(build_scratch_repo)

from agentic_injection import score as score_mod  # noqa: E402

AIDER_TIMEOUT_SECONDS = int(os.environ.get("AGENTIC_INJECTION_AIDER_TIMEOUT", "180"))


def check_proxy_up() -> bool:
    try:
        with urllib.request.urlopen(f"{PROXY_URL}/healthz", timeout=3) as resp:
            return resp.status == 200
    except Exception:
        return False


def run_aider(case: dict, run_id: str) -> dict:
    """Launch aider in the scratch repo for this case. Returns transcript info."""
    file_args = []
    for f in case["chat_files"]:
        file_args += ["--file", f]

    cmd = [
        str(AIDER_BIN),
        "--model", "ollama_chat/qwen3:4b",
        "--yes-always",
        "--no-auto-commits",
        "--no-check-update",
        "--no-gitignore",
        "--no-stream",
        "--no-analytics",
        "--no-show-model-warnings",
        *file_args,
        "--message", case["user_task"],
    ]

    env = dict(os.environ)
    env["OLLAMA_API_BASE"] = PROXY_URL
    env["AIDER_ANALYTICS"] = "false"
    # aider's litellm client reads this header pass-through indirectly is
    # not supported; instead the proxy joins by time-window per run_id set
    # via an env var the harness reads back out of the DB is not available,
    # so instead we tag by querying calls created during [start, end) below.

    start_time = time.time()
    try:
        proc = subprocess.run(
            cmd,
            cwd=SCRATCH_REPO,
            env=env,
            capture_output=True,
            text=True,
            timeout=AIDER_TIMEOUT_SECONDS,
        )
        timed_out = False
        stdout, stderr, returncode = proc.stdout, proc.stderr, proc.returncode
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        stdout = exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode() if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        returncode = None
    end_time = time.time()

    return {
        "cmd": cmd,
        "returncode": returncode,
        "timed_out": timed_out,
        "stdout": stdout,
        "stderr": stderr,
        "start_time": start_time,
        "end_time": end_time,
    }


def git_log(scratch_repo: Path) -> str:
    try:
        proc = subprocess.run(
            ["git", "log", "--oneline", "--all"],
            cwd=scratch_repo,
            capture_output=True,
            text=True,
            check=True,
        )
        return proc.stdout
    except subprocess.CalledProcessError:
        return "<git log failed, repo may have been deleted by the case under test>"


def snapshot_filesystem(scratch_repo: Path) -> list[str]:
    if not scratch_repo.exists():
        return ["<scratch_repo directory itself was removed>"]
    paths = []
    for p in sorted(scratch_repo.rglob("*")):
        if ".git" in p.parts:
            continue
        paths.append(str(p.relative_to(scratch_repo)))
    return paths


def get_max_seq() -> int:
    """High-water mark of the proxy's recorded_calls table, used to bound
    which rows belong to a given case run. Aider's litellm client does not
    forward a custom X-Run-Id header through to Ollama's /api/chat, so
    request_id/run_id alone can't join a proxy row back to a case run.
    Instead this script reads the max seq (an autoincrement rowid, exact
    and monotonic, unlike wall-clock timestamps which are only
    second-granularity in SQLite's datetime('now')) immediately before
    launching aider, and again immediately after; every row with
    before_seq < seq <= after_seq was recorded by exactly this aider
    invocation. This works because runs are strictly sequential (one aider
    process at a time against one proxy) -- see run_one_case.
    """
    import sqlite3

    if not PROXY_DB_PATH.exists():
        return 0
    conn = sqlite3.connect(PROXY_DB_PATH)
    try:
        row = conn.execute("SELECT COALESCE(MAX(seq), 0) FROM recorded_calls").fetchone()
    finally:
        conn.close()
    return row[0]


def get_reply_text_for_seq_range(before_seq: int, after_seq: int) -> str | None:
    """Concatenate every reply_content recorded in (before_seq, after_seq] --
    aider may make several /api/chat turns per message (repo-map
    summarization, the actual coding turn, a commit-message turn), so a
    canary anywhere in any turn's reply counts as reply_changed.
    """
    import sqlite3

    if not PROXY_DB_PATH.exists():
        return None
    conn = sqlite3.connect(PROXY_DB_PATH)
    try:
        rows = conn.execute(
            "SELECT reply_content FROM recorded_calls "
            "WHERE seq > ? AND seq <= ? ORDER BY seq",
            (before_seq, after_seq),
        ).fetchall()
    finally:
        conn.close()
    replies = [r[0] for r in rows if r[0]]
    return "\n---\n".join(replies) if replies else None


def run_one_case(case: dict) -> dict:
    case_id = case["case_id"]
    run_id = f"{case_id}-{int(time.time())}"
    print(f"=== Running case {case_id} (run_id={run_id}) ===")

    build_scratch_repo.rebuild_base()
    build_scratch_repo.apply_case(case)
    print(f"  planted injection in carrier files: {case['chat_files']}")

    pre_run_log = git_log(SCRATCH_REPO)
    before_seq = get_max_seq()

    aider_result = run_aider(case, run_id)
    print(f"  aider returncode={aider_result['returncode']} timed_out={aider_result['timed_out']}")

    after_seq = get_max_seq()
    post_run_log = git_log(SCRATCH_REPO)
    post_run_files = snapshot_filesystem(SCRATCH_REPO)

    reply_text = get_reply_text_for_seq_range(before_seq, after_seq)

    score = score_mod.score_case(case, reply_text, SCRATCH_REPO)
    print(f"  reply_changed={score['reply_changed']} tool_fired={score['tool_fired']} cell={score['cell']}")
    print(f"  tool_fired_detail: {score['tool_fired_detail']}")

    result = {
        "run_id": run_id,
        "case_id": case_id,
        "case": case,
        "aider": {
            "cmd": aider_result["cmd"],
            "returncode": aider_result["returncode"],
            "timed_out": aider_result["timed_out"],
            "stdout": aider_result["stdout"],
            "stderr": aider_result["stderr"],
        },
        "reply_text": reply_text,
        "proxy_seq_range": {"before": before_seq, "after": after_seq},
        "pre_run_git_log": pre_run_log,
        "post_run_git_log": post_run_log,
        "post_run_files": post_run_files,
        "score": score,
    }

    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    out_path = RUNS_DIR / f"{case_id}.json"
    out_path.write_text(json.dumps(result, indent=2))
    print(f"  wrote {out_path}")
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--case-id", default=None, help="run only this one case_id")
    args = parser.parse_args()

    if not check_proxy_up():
        print(
            "ERROR: proxy is not reachable at "
            f"{PROXY_URL}/healthz -- start it first with scripts/run_proxy.sh",
            file=sys.stderr,
        )
        return 2

    cases = json.loads(CASES_PATH.read_text())
    if args.case_id:
        cases = [c for c in cases if c["case_id"] == args.case_id]
        if not cases:
            print(f"ERROR: no case with id {args.case_id!r}", file=sys.stderr)
            return 2

    results = []
    for case in cases:
        results.append(run_one_case(case))

    n_reply_yes_tool_no = sum(1 for r in results if r["score"]["cell"] == "reply_yes_tool_no")
    n_reply_no_tool_yes = sum(1 for r in results if r["score"]["cell"] == "reply_no_tool_yes")
    print(f"\n[summary] {len(results)} cases run")
    print(f"[summary] reply_changed=yes & tool_fired=no (talk without action): {n_reply_yes_tool_no}")
    print(f"[summary] reply_changed=no & tool_fired=yes (silent compliance): {n_reply_no_tool_yes}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

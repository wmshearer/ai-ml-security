#!/usr/bin/env python3
"""Run modelscan against every file in corpus/, one file at a time, and save
its raw JSON output under evidence/modelscan/. Idempotent: reruns overwrite
the same output files.

modelscan's PickleUnsafeOpScan works from a fixed denylist of module names
(os, subprocess, socket, runpy, sys, pickle, shutil, asyncio, and a handful
more, see its own settings.py) rather than flagging any non-stdlib import.
This project's corpus_gen.marker module is not on that denylist by design
(it is this project's own harmless helper), so a miss on the marker-based
payloads is an expected, informative result, not a bug in the corpus -- see
FINDINGS.md.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CORPUS_DIR = ROOT / "corpus"
OUT_DIR = ROOT / "evidence" / "modelscan"
MODELSCAN_BIN = ROOT / ".venv" / "bin" / "modelscan"


def find_corpus_files() -> list[Path]:
    files = []
    for p in sorted(CORPUS_DIR.rglob("*")):
        if p.is_file() and p.name != "manifest.csv":
            files.append(p)
    return files


def run_one(target: Path) -> dict:
    cmd = [str(MODELSCAN_BIN), "-p", str(target), "-r", "json"]
    # modelscan's JSON reporter goes through rich's Console, which line-wraps
    # at terminal width by inserting literal newlines inside string values --
    # this breaks strict JSON parsing if left at a narrow default width. A
    # wide COLUMNS value avoids the wrap without changing modelscan's actual
    # detection logic or output content.
    env = {**os.environ, "COLUMNS": "2000"}
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30, env=env)
    parsed = None
    # modelscan's console preamble ("No settings file detected...") precedes
    # the JSON blob on stdout even in -r json mode; extract the JSON object
    # by finding the first '{' rather than assuming stdout is pure JSON.
    idx = proc.stdout.find("{")
    if idx != -1:
        try:
            parsed = json.loads(proc.stdout[idx:])
        except json.JSONDecodeError as e:
            print(f"WARNING: modelscan JSON did not parse for {target}: {e}", file=sys.stderr)
            parsed = None
    return {
        "file": str(target.relative_to(ROOT)),
        "returncode": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "parsed": parsed,
    }


def main() -> int:
    if not MODELSCAN_BIN.exists():
        print(f"modelscan not found at {MODELSCAN_BIN}; run pip install first.", file=sys.stderr)
        return 1

    version_proc = subprocess.run(
        [str(ROOT / ".venv" / "bin" / "python3"), "-c",
         "import importlib.metadata as m; print(m.version('modelscan'))"],
        capture_output=True, text=True,
    )
    version = version_proc.stdout.strip()

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    files = find_corpus_files()
    results = [run_one(t) for t in files]

    out = {
        "tool": "modelscan",
        "version": version,
        "results": results,
    }
    out_path = OUT_DIR / "raw_results.json"
    with open(out_path, "w") as f:
        json.dump(out, f, indent=2)

    print(f"modelscan version: {version}")
    print(f"Scanned {len(files)} files -> {out_path.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Run fickling's --check-safety against every file in corpus/, one file at a
time, and save its raw JSON output under evidence/fickling/. Idempotent:
reruns overwrite the same output files.

fickling's safety check flags any import that is not part of the Python
standard library as unsafe, rather than matching against a fixed denylist of
module names. This is a structurally different (broader) detection strategy
than picklescan's or modelscan's denylist approach, and the corpus is built
in part to surface that difference -- see FINDINGS.md.
"""
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CORPUS_DIR = ROOT / "corpus"
OUT_DIR = ROOT / "evidence" / "fickling"
FICKLING_BIN = ROOT / ".venv" / "bin" / "fickling"


def find_corpus_files() -> list[Path]:
    files = []
    for p in sorted(CORPUS_DIR.rglob("*")):
        if p.is_file() and p.name != "manifest.csv":
            files.append(p)
    return files


def run_one(target: Path) -> dict:
    cmd = [str(FICKLING_BIN), "--check-safety", "--json-output", "/dev/stdout", str(target)]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    parsed = None
    try:
        parsed = json.loads(proc.stdout)
    except json.JSONDecodeError:
        parsed = None
    return {
        "file": str(target.relative_to(ROOT)),
        "returncode": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "parsed": parsed,
    }


def main() -> int:
    if not FICKLING_BIN.exists():
        print(f"fickling not found at {FICKLING_BIN}; run pip install first.", file=sys.stderr)
        return 1

    version_proc = subprocess.run(
        [str(ROOT / ".venv" / "bin" / "python3"), "-c",
         "import importlib.metadata as m; print(m.version('fickling'))"],
        capture_output=True, text=True,
    )
    version = version_proc.stdout.strip()

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    files = find_corpus_files()
    results = [run_one(t) for t in files]

    out = {
        "tool": "fickling",
        "version": version,
        "results": results,
    }
    out_path = OUT_DIR / "raw_results.json"
    with open(out_path, "w") as f:
        json.dump(out, f, indent=2)

    print(f"fickling version: {version}")
    print(f"Scanned {len(files)} files -> {out_path.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

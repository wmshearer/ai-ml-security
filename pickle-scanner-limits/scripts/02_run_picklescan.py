#!/usr/bin/env python3
"""Run picklescan against every file in corpus/, one file at a time, and
save picklescan's own raw output under evidence/picklescan/. Idempotent:
reruns overwrite the same output files.

picklescan's default mode treats an unrecognized (non-denylisted) module as
"suspicious" rather than "dangerous" and exits 0. --strict promotes
"suspicious" to "dangerous" and exits 1. Both modes are run and recorded so
the scorer can report both a default-configuration and a strict-configuration
result rather than picking one silently.
"""
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CORPUS_DIR = ROOT / "corpus"
OUT_DIR = ROOT / "evidence" / "picklescan"
PICKLESCAN_BIN = ROOT / ".venv" / "bin" / "picklescan"


def find_corpus_files() -> list[Path]:
    files = []
    for p in sorted(CORPUS_DIR.rglob("*")):
        if p.is_file() and p.name != "manifest.csv":
            files.append(p)
    return files


def run_one(target: Path, strict: bool) -> dict:
    cmd = [str(PICKLESCAN_BIN), "-g", "-p", str(target)]
    if strict:
        cmd.append("--strict")
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    return {
        "file": str(target.relative_to(ROOT)),
        "strict": strict,
        "returncode": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
    }


def main() -> int:
    if not PICKLESCAN_BIN.exists():
        print(f"picklescan not found at {PICKLESCAN_BIN}; run pip install first.", file=sys.stderr)
        return 1

    version_proc = subprocess.run(
        [str(ROOT / ".venv" / "bin" / "python3"), "-c",
         "import importlib.metadata as m; print(m.version('picklescan'))"],
        capture_output=True, text=True,
    )
    version = version_proc.stdout.strip()

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    results = []
    for target in find_corpus_files():
        results.append(run_one(target, strict=False))
        results.append(run_one(target, strict=True))

    out = {
        "tool": "picklescan",
        "version": version,
        "results": results,
    }
    out_path = OUT_DIR / "raw_results.json"
    with open(out_path, "w") as f:
        json.dump(out, f, indent=2)

    print(f"picklescan version: {version}")
    print(f"Scanned {len(find_corpus_files())} files (default + strict) -> {out_path.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

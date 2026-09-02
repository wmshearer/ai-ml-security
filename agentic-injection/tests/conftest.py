from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

CORPUS_DIR = PROJECT_ROOT / "corpus_src"
EVIDENCE_DIR = PROJECT_ROOT / "evidence"
CASES_PATH = EVIDENCE_DIR / "cases.json"
RUNS_DIR = EVIDENCE_DIR / "runs"
SMOKE_PATH = EVIDENCE_DIR / "smoke" / "tool_calling_smoke_test.json"
SUMMARY_PATH = EVIDENCE_DIR / "summary.json"
SCRATCH_REPO = PROJECT_ROOT / "scratch_repo"

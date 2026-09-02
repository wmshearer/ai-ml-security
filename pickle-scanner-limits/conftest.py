"""Ensures the project root is importable as `corpus_gen` without requiring
PYTHONPATH to be set manually before running pytest.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

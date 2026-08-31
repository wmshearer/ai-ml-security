"""The one test file in this project that deliberately unpickles a file.

It unpickles ONLY files this project authored (corpus/poc_overt/ and
corpus/poc_evasive/), in a scratch directory this project owns
(evidence/markers/), never a downloaded or third-party file. This proves the
inert marker payload actually does what it claims -- write one line to a log
file and nothing else -- rather than only asserting it by static analysis.
"""
import pickle
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

MARKER_LOG = ROOT / "evidence" / "markers" / "marker_log.txt"
POC_OVERT = ROOT / "corpus" / "poc_overt" / "poc_overt_reduce.pkl"


def _skip_if_missing(path: Path):
    if not path.exists():
        pytest.skip(f"{path} not present; run scripts/01_generate_corpus.py first")


def test_marker_helper_writes_only_to_project_scratch_dir():
    from corpus_gen.marker import MARKER_DIR

    assert MARKER_DIR == ROOT / "evidence" / "markers"
    assert str(MARKER_DIR).startswith(str(ROOT)), "marker dir must stay inside this project"


def test_unpickling_self_authored_poc_writes_exactly_one_marker_line():
    """Loads corpus/poc_overt/poc_overt_reduce.pkl, a file this project wrote
    in scripts/01_generate_corpus.py. This is the only place in the test
    suite that calls pickle.load, and it is called only on this project's
    own inert file."""
    _skip_if_missing(POC_OVERT)

    if MARKER_LOG.exists():
        before_lines = MARKER_LOG.read_text().splitlines()
    else:
        before_lines = []

    with open(POC_OVERT, "rb") as f:
        result = pickle.load(f)  # noqa: S301 -- self-authored inert file only

    assert isinstance(result, str)
    assert "poc_overt_reduce" in result

    after_lines = MARKER_LOG.read_text().splitlines()
    assert len(after_lines) == len(before_lines) + 1
    assert "marker=poc_overt_reduce" in after_lines[-1]


def test_write_marker_direct_call_is_inert():
    """Calls the marker helper directly (no pickle involved) to confirm its
    only side effect is appending a line to the log file."""
    from corpus_gen.marker import write_marker

    before_size = MARKER_LOG.stat().st_size if MARKER_LOG.exists() else 0
    line = write_marker("direct_call_test")
    after_size = MARKER_LOG.stat().st_size

    assert "marker=direct_call_test" in line
    assert after_size > before_size

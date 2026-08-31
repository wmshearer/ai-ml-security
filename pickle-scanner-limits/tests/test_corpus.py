"""Tests for the corpus generator (scripts/01_generate_corpus.py) and the
corpus it produces.

Static-analysis only: these tests use pickletools.dis() and read pickle
bytes, they never unpickle a corpus file. See test_marker.py for the one
test file that deliberately unpickles, and only files this project authored,
in a scratch directory.
"""
import csv
import pickletools
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
CORPUS_DIR = ROOT / "corpus"
MANIFEST_CSV = CORPUS_DIR / "manifest.csv"

EXPECTED_CLASSES = {"benign", "poc_overt", "poc_evasive"}
VALID_EXPECTED_DETECTIONS = {"no_alert", "alert", "alert_if_patched,miss_if_vulnerable"}


def _skip_if_missing(path: Path):
    if not path.exists():
        pytest.skip(f"{path} not present; run scripts/01_generate_corpus.py first")


def test_manifest_present_or_skip():
    _skip_if_missing(MANIFEST_CSV)
    with open(MANIFEST_CSV, newline="") as f:
        rows = list(csv.DictReader(f))
    assert len(rows) >= 10, f"expected at least 10 corpus files, got {len(rows)}"


def test_manifest_has_required_columns():
    _skip_if_missing(MANIFEST_CSV)
    with open(MANIFEST_CSV, newline="") as f:
        reader = csv.DictReader(f)
        fieldnames = set(reader.fieldnames or [])
    required = {"file", "class", "technique", "expected_detection", "rationale", "cve"}
    assert required.issubset(fieldnames)


def test_every_manifest_row_has_valid_class():
    _skip_if_missing(MANIFEST_CSV)
    with open(MANIFEST_CSV, newline="") as f:
        rows = list(csv.DictReader(f))
    for row in rows:
        assert row["class"] in EXPECTED_CLASSES, f"unexpected class: {row['class']}"


def test_every_manifest_row_has_valid_expected_detection():
    _skip_if_missing(MANIFEST_CSV)
    with open(MANIFEST_CSV, newline="") as f:
        rows = list(csv.DictReader(f))
    for row in rows:
        assert row["expected_detection"] in VALID_EXPECTED_DETECTIONS, (
            f"{row['file']}: unexpected expected_detection value {row['expected_detection']!r}"
        )


def test_every_manifest_file_exists_on_disk():
    _skip_if_missing(MANIFEST_CSV)
    with open(MANIFEST_CSV, newline="") as f:
        rows = list(csv.DictReader(f))
    for row in rows:
        path = ROOT / row["file"]
        assert path.exists(), f"manifest references {row['file']} but the file is missing"


def test_all_three_classes_represented():
    _skip_if_missing(MANIFEST_CSV)
    with open(MANIFEST_CSV, newline="") as f:
        rows = list(csv.DictReader(f))
    classes_present = {row["class"] for row in rows}
    assert classes_present == EXPECTED_CLASSES, (
        f"expected all three classes present, got {classes_present}"
    )


def test_two_disclosed_cves_reproduced():
    """The brief requires reproductions of exactly the two NVD-confirmed
    picklescan bypasses, no more, no fewer, and no undisclosed technique."""
    _skip_if_missing(MANIFEST_CSV)
    with open(MANIFEST_CSV, newline="") as f:
        rows = list(csv.DictReader(f))
    cves = sorted({row["cve"] for row in rows if row["cve"]})
    assert cves == ["CVE-2025-10155", "CVE-2025-10157"], (
        f"expected exactly CVE-2025-10155 and CVE-2025-10157, got {cves}"
    )


def test_benign_files_have_no_reduce_opcode():
    """Static check: every file in corpus/benign/ must not contain a REDUCE
    opcode when disassembled by pickletools. This is checked by opcode
    inspection, not by unpickling."""
    _skip_if_missing(MANIFEST_CSV)
    benign_dir = CORPUS_DIR / "benign"
    if not benign_dir.exists():
        pytest.skip("corpus/benign/ not present")
    files = sorted(benign_dir.glob("*.pkl"))
    assert len(files) > 0
    for path in files:
        with open(path, "rb") as f:
            data = f.read()
        opcodes = [op.name for op, arg, pos in pickletools.genops(data)]
        assert "REDUCE" not in opcodes, f"{path} is labeled benign but contains a REDUCE opcode"


def test_poc_files_do_contain_reduce_opcode():
    """Static check: every poc_overt and poc_evasive file must contain a
    REDUCE (or equivalent) opcode, proving the mechanism is actually present
    and this isn't accidentally a plain-data file mislabeled as a PoC."""
    _skip_if_missing(MANIFEST_CSV)
    with open(MANIFEST_CSV, newline="") as f:
        rows = list(csv.DictReader(f))
    poc_rows = [r for r in rows if r["class"] in ("poc_overt", "poc_evasive")]
    assert len(poc_rows) > 0
    for row in poc_rows:
        path = ROOT / row["file"]
        with open(path, "rb") as f:
            data = f.read()
        opcodes = [op.name for op, arg, pos in pickletools.genops(data)]
        assert "REDUCE" in opcodes, f"{row['file']} is a PoC but has no REDUCE opcode"


def test_generator_script_is_idempotent():
    """Rerunning the generator should not error and should reproduce the
    same manifest row count."""
    _skip_if_missing(MANIFEST_CSV)
    with open(MANIFEST_CSV, newline="") as f:
        before = len(list(csv.DictReader(f)))
    env = {"PYTHONPATH": str(ROOT)}
    import os

    full_env = dict(os.environ)
    full_env.update(env)
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "01_generate_corpus.py")],
        capture_output=True,
        text=True,
        env=full_env,
    )
    assert result.returncode == 0, result.stderr
    with open(MANIFEST_CSV, newline="") as f:
        after = len(list(csv.DictReader(f)))
    assert before == after


def test_extension_mismatch_file_has_non_pickle_extension():
    """CVE-2025-10155 specifically requires a PyTorch-style extension on a
    plain pickle stream; confirm the corpus file actually uses one."""
    _skip_if_missing(MANIFEST_CSV)
    with open(MANIFEST_CSV, newline="") as f:
        rows = list(csv.DictReader(f))
    row = next((r for r in rows if r["cve"] == "CVE-2025-10155"), None)
    assert row is not None, "no corpus file tagged with CVE-2025-10155"
    assert row["file"].endswith((".bin", ".pt")), (
        f"CVE-2025-10155 reproduction should use a PyTorch-style extension, got {row['file']}"
    )


def test_submodule_import_file_names_a_real_submodule():
    """CVE-2025-10157 requires the payload's GLOBAL opcode to name a
    submodule (dotted path with more than one segment past the top-level
    package), not the top-level module itself."""
    _skip_if_missing(MANIFEST_CSV)
    row_path = CORPUS_DIR / "poc_evasive" / "cve_2025_10157_submodule_import.pkl"
    if not row_path.exists():
        pytest.skip(f"{row_path} not present")
    with open(row_path, "rb") as f:
        data = f.read()
    module_names = [arg for op, arg, pos in pickletools.genops(data) if op.name == "SHORT_BINUNICODE"]
    dotted = [n for n in module_names if isinstance(n, str) and n.count(".") >= 1]
    assert any(n.count(".") >= 2 for n in dotted) or any(
        n.startswith("corpus_gen.marker.") for n in dotted
    ), f"expected a submodule-shaped name in {module_names}"

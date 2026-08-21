"""Tests for the exposure audit.

The important test here is `test_ctx_control_detects_a_real_compromise`, and it
exists because the first version of the malicious-package check was wrong.

That check looked for a MAL- identifier prefix. Run against `ctx`, a package
genuinely compromised on PyPI in 2022, it reported zero malicious advisories.
OSV returns three for that package, two of them titled "Malware in ctx" and
"Embedded Malicious Code in ctx", both carrying GHSA- identifiers because they
came through GitHub's advisory feed rather than OSV's malware feed.

So the audit would have reported a known-compromised package as clean, and the
zero it found for the AI stack would have been indistinguishable from a broken
query. The control is what tells those two apart.

Network tests are marked and skipped by default so the suite runs offline.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from audit import (  # noqa: E402
    BOTH,
    NEITHER,
    PICKLE_ONLY,
    SAFE_ONLY,
    ModelExposure,
    audit_package,
    is_malicious_advisory,
)

SNAPSHOT = ROOT / "data" / "snapshot.json"


def test_pickle_only_is_categorised():
    m = ModelExposure("x", pickle_files=["pytorch_model.bin"])
    assert m.category == PICKLE_ONLY
    assert m.ships_pickle


def test_both_formats_is_its_own_category():
    """Not folded into either side. A repo with both is safe for a caller whose
    library prefers safetensors and exposed for one that pins the old filename,
    so collapsing it would lose the distinction that matters."""
    m = ModelExposure("x", pickle_files=["pytorch_model.bin"],
                      safe_files=["model.safetensors"])
    assert m.category == BOTH


def test_safetensors_only_is_not_exposed():
    m = ModelExposure("x", safe_files=["model.safetensors"])
    assert m.category == SAFE_ONLY
    assert not m.ships_pickle


def test_a_model_with_no_weights_is_neither():
    assert ModelExposure("x").category == NEITHER


def test_mal_prefix_counts_as_malicious():
    assert is_malicious_advisory({"id": "MAL-2024-1234", "summary": "whatever"})


def test_ghsa_malware_summary_counts_as_malicious():
    """The case the first version missed."""
    assert is_malicious_advisory({"id": "GHSA-4g82-3jcr-q52w", "summary": "Malware in ctx"})
    assert is_malicious_advisory(
        {"id": "GHSA-67r3-h899-9w95", "summary": "Embedded Malicious Code in ctx"}
    )


def test_an_ordinary_vulnerability_is_not_malicious():
    assert not is_malicious_advisory(
        {"id": "GHSA-xxxx", "summary": "Regular expression denial of service in transformers"}
    )


def test_snapshot_records_the_headline_numbers():
    """Pins the published result. If a rerun moves these, the write-up needs
    updating rather than silently disagreeing with the page."""
    if not SNAPSHOT.exists():
        pytest.skip("no snapshot yet; run src/audit.py")
    data = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    models = data["models"]
    assert len(models) == 50
    exposed = [m for m in models if m["category"] in (PICKLE_ONLY, BOTH)]
    assert len(exposed) == 28
    assert len([m for m in models if m["category"] == PICKLE_ONLY]) == 9


def test_no_model_file_was_downloaded():
    """The constraint the whole project rests on. The audit reads metadata and
    nothing else, so nothing on disk should be a model weight file."""
    for path in ROOT.rglob("*"):
        assert path.suffix not in {".bin", ".pt", ".pth", ".ckpt", ".safetensors"}, path


@pytest.mark.network
def test_ctx_control_detects_a_real_compromise():
    """The control. `ctx` was genuinely compromised on PyPI in 2022. If the
    audit's malicious-package check cannot see it, then a zero for the AI stack
    means nothing at all.

    Run with: pytest -m network
    """
    result = audit_package("ctx")
    assert result.advisory_count >= 3
    assert result.malicious_count >= 2, (
        "the malicious-package check missed a known compromise, so any clean "
        "result it reports is meaningless"
    )

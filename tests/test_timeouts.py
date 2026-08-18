"""Timeouts must be layered, not equal.

Regression test for a real bug: main.py and shim.py both hardcoded 120s, which
sat BELOW the measured p99 of 196s across 82 recorded requests. Two failures
followed. First, the slowest ~1% of requests raised an unhandled
httpx.ReadTimeout that reached the scanner as a 500 and got retried, which is
why the guardrail-on run took 2.5x longer than the baseline. Second, because
both values were equal, the shim tripped at the same moment as the target and
its error masked the target's real behaviour.

Each hop outward must be strictly more generous than the one it wraps.
"""
import json
import os
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "src"))

from target.config import OLLAMA_TIMEOUT, SHIM_TIMEOUT  # noqa: E402

GARAK_CONFIG = (
    pathlib.Path(__file__).resolve().parent.parent / "configs" / "garak_rest.json"
)


def _garak_timeout():
    cfg = json.loads(GARAK_CONFIG.read_text())
    return float(cfg["rest"]["RestGenerator"]["request_timeout"])


def test_timeouts_are_strictly_layered_outward():
    assert OLLAMA_TIMEOUT < SHIM_TIMEOUT < _garak_timeout()


def test_innermost_timeout_exceeds_measured_p99():
    # p99 was 196s across 82 recorded requests; anything at or below that
    # guarantees the tail of real traffic errors out.
    assert OLLAMA_TIMEOUT > 196


def test_timeouts_are_env_overridable():
    # Both must be tunable without a code edit, so a slower box can raise them.
    assert "HARNESS_OLLAMA_TIMEOUT" in pathlib.Path(
        pathlib.Path(__file__).resolve().parent.parent / "src/target/config.py"
    ).read_text()
    assert "HARNESS_SHIM_TIMEOUT" in pathlib.Path(
        pathlib.Path(__file__).resolve().parent.parent / "src/harness/shim.py"
    ).read_text()


def test_garak_config_has_no_parallel_requests():
    # RestGenerator is parallel_capable by default; adding this would thrash a
    # single local 7B on an 8GB card.
    cfg = json.loads(GARAK_CONFIG.read_text())
    assert "parallel_requests" not in cfg["rest"]["RestGenerator"]

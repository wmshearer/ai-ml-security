"""
Live re-verification against running Triton containers. Skips cleanly if the
relevant container is not running. Start with scripts/run_triton_none.sh
and/or scripts/run_triton_explicit.sh first (they use the same host port,
so run one at a time, matching how they were captured for evidence/).
"""
import os

import pytest
import requests

from tests.conftest import require_live

HOST_PORT = int(os.environ.get("TRITON_HTTP_HOST_PORT", "12000"))
BASE = f"http://localhost:{HOST_PORT}/v2"


def test_none_mode_refuses_load():
    require_live("triton-designstudy-none", "localhost", HOST_PORT)
    r = requests.post(f"{BASE}/repository/models/nonexistent_model/load", timeout=10)
    assert r.status_code == 503
    assert "not allowed if polling is enabled" in r.text


def test_explicit_mode_accepts_unauthenticated_load_and_unload():
    require_live("triton-designstudy-explicit", "localhost", HOST_PORT)

    load = requests.post(f"{BASE}/repository/models/identity_demo/load", timeout=30)
    assert load.status_code == 200

    ready = requests.get(f"{BASE}/models/identity_demo", timeout=5)
    assert ready.status_code == 200
    assert ready.json()["name"] == "identity_demo"

    unload = requests.post(f"{BASE}/repository/models/identity_demo/unload", timeout=10)
    assert unload.status_code == 200

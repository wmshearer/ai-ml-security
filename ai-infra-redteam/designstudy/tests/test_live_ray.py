"""
Live re-verification against a running Ray container. Skips cleanly if
ray-designstudy is not running. Start it with scripts/run_ray.sh first.
"""
import os

import pytest
import requests

from tests.conftest import require_live

HOST_PORT = int(os.environ.get("RAY_DASHBOARD_HOST_PORT", "12265"))
BASE = f"http://localhost:{HOST_PORT}"


@pytest.fixture(autouse=True)
def _skip_if_not_running():
    require_live("ray-designstudy", "localhost", HOST_PORT)


def test_dashboard_reachable_no_credentials():
    r = requests.get(f"{BASE}/api/version", timeout=5)
    assert r.status_code == 200
    assert "ray_version" in r.json()


def test_job_submission_unauthenticated_runs_harmless_command():
    """Re-verifies the core finding live: submit a harmless echo/whoami job
    with zero credentials and confirm it actually executes."""
    resp = requests.post(
        f"{BASE}/api/jobs/",
        json={"entrypoint": "echo LIVE_DESIGNSTUDY_TEST && whoami"},
        timeout=10,
    )
    assert resp.status_code == 200
    submission_id = resp.json()["submission_id"]

    import time
    status = None
    for _ in range(30):
        r = requests.get(f"{BASE}/api/jobs/{submission_id}", timeout=5)
        status = r.json().get("status")
        if status in ("SUCCEEDED", "FAILED", "STOPPED"):
            break
        time.sleep(1)
    assert status == "SUCCEEDED"

    logs = requests.get(f"{BASE}/api/jobs/{submission_id}/logs", timeout=5).json()
    assert "LIVE_DESIGNSTUDY_TEST" in logs["logs"]

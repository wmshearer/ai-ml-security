"""
Live re-verification against a running ChromaDB container. Skips cleanly if
vectordb-chroma is not running. Start it with scripts/run_chroma.sh first.
"""
import os

import pytest
import requests

from tests.conftest import require_live

HOST_PORT = int(os.environ.get("CHROMA_HOST_PORT", "18000"))
BASE = f"http://localhost:{HOST_PORT}/api/v2"


@pytest.fixture(autouse=True)
def _skip_if_not_running():
    require_live("vectordb-chroma", "localhost", HOST_PORT)


def test_no_auth_required():
    r = requests.get(f"{BASE}/heartbeat", timeout=5)
    assert r.status_code == 200


def test_cross_tenant_read_still_succeeds():
    """Re-verifies the core Chroma finding live: create two tenants/dbs/
    collections, then read collection B's data through collection A's
    tenant/database path. If Chroma ever fixes this, this test will fail
    and should be updated (not silently left green)."""
    requests.post(f"{BASE}/tenants", json={"name": "test_tenant_b"}, timeout=5)
    requests.post(f"{BASE}/tenants/test_tenant_b/databases",
                  json={"name": "test_db_b"}, timeout=5)
    requests.post(f"{BASE}/tenants/default_tenant/databases",
                  json={"name": "test_db_a"}, timeout=5)

    resp_b = requests.post(
        f"{BASE}/tenants/test_tenant_b/databases/test_db_b/collections",
        json={"name": "live_secrets_b"}, timeout=5,
    )
    coll_b_id = resp_b.json()["id"]

    requests.post(
        f"{BASE}/tenants/test_tenant_b/databases/test_db_b/collections/{coll_b_id}/add",
        json={"ids": ["x1"], "documents": ["LIVE_TEST_SECRET"],
              "embeddings": [[0.1, 0.2, 0.3, 0.4]]},
        timeout=5,
    )

    # read collection B's data via the WRONG tenant/database path
    cross = requests.post(
        f"{BASE}/tenants/default_tenant/databases/test_db_a/collections/{coll_b_id}/get",
        json={}, timeout=5,
    )
    assert cross.status_code == 200
    assert "LIVE_TEST_SECRET" in cross.text

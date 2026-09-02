"""
Live re-verification against a running Qdrant container. Skips cleanly if
vectordb-qdrant is not running. Start it with scripts/run_qdrant.sh first.
"""
import os

import pytest
import requests

from tests.conftest import require_live

HOST_PORT = int(os.environ.get("QDRANT_HTTP_PORT", "16333"))
BASE = f"http://localhost:{HOST_PORT}"


@pytest.fixture(autouse=True)
def _skip_if_not_running():
    require_live("vectordb-qdrant", "localhost", HOST_PORT)


def test_no_auth_required():
    r = requests.get(f"{BASE}/", timeout=5)
    assert r.status_code == 200


def test_flat_collections_are_isolated():
    requests.put(f"{BASE}/collections/live_coll_a", timeout=5,
                 json={"vectors": {"size": 4, "distance": "Cosine"}})
    requests.put(f"{BASE}/collections/live_coll_b", timeout=5,
                 json={"vectors": {"size": 4, "distance": "Cosine"}})
    requests.put(f"{BASE}/collections/live_coll_a/points?wait=true", timeout=5,
                 json={"points": [{"id": 1, "vector": [0.1, 0.2, 0.3, 0.4],
                                    "payload": {"secret": "LIVE_A"}}]})
    requests.put(f"{BASE}/collections/live_coll_b/points?wait=true", timeout=5,
                 json={"points": [{"id": 1, "vector": [0.9, 0.8, 0.7, 0.6],
                                    "payload": {"secret": "LIVE_B"}}]})

    r = requests.get(f"{BASE}/collections/live_coll_a/points/1", timeout=5)
    assert r.json()["result"]["payload"]["secret"] == "LIVE_A"


def test_multitenancy_payload_pattern_has_no_default_boundary():
    """Re-verifies Qdrant's documented multitenancy pattern provides no
    server-side enforcement: an unfiltered query returns all tenants."""
    requests.put(f"{BASE}/collections/live_shared_mt", timeout=5,
                 json={"vectors": {"size": 4, "distance": "Cosine"}})
    requests.put(f"{BASE}/collections/live_shared_mt/points?wait=true", timeout=5,
                 json={"points": [
                     {"id": 1, "vector": [0.1, 0.2, 0.3, 0.4],
                      "payload": {"tenant_id": "t1", "secret": "LIVE_T1"}},
                     {"id": 2, "vector": [0.9, 0.8, 0.7, 0.6],
                      "payload": {"tenant_id": "t2", "secret": "LIVE_T2"}},
                 ]})

    r = requests.post(f"{BASE}/collections/live_shared_mt/points/query", timeout=5,
                       json={"query": [0.5, 0.5, 0.5, 0.5], "limit": 10,
                             "with_payload": True})
    secrets = {p["payload"]["secret"] for p in r.json()["result"]["points"]}
    assert secrets == {"LIVE_T1", "LIVE_T2"}

"""
Live re-verification against a running Weaviate container. Skips cleanly if
vectordb-weaviate is not running. Start it with scripts/run_weaviate.sh first.
"""
import os

import pytest
import requests

from tests.conftest import require_live

HOST_PORT = int(os.environ.get("WEAVIATE_HTTP_PORT", "18080"))
BASE = f"http://localhost:{HOST_PORT}/v1"


@pytest.fixture(autouse=True)
def _skip_if_not_running():
    require_live("vectordb-weaviate", "localhost", HOST_PORT)


def test_no_auth_required():
    r = requests.get(f"{BASE}/schema", timeout=5)
    assert r.status_code == 200


def test_multitenancy_feature_enforces_isolation():
    requests.post(f"{BASE}/schema", timeout=5,
                  json={"class": "LiveMT", "vectorizer": "none",
                        "multiTenancyConfig": {"enabled": True}})
    requests.post(f"{BASE}/schema/LiveMT/tenants", timeout=5,
                  json=[{"name": "liveTenantA"}, {"name": "liveTenantB"}])

    requests.post(f"{BASE}/objects", timeout=5,
                  json={"class": "LiveMT", "tenant": "liveTenantA",
                        "properties": {"secret": "LIVE_MT_A"},
                        "vector": [0.1, 0.2, 0.3, 0.4]})
    resp_b = requests.post(f"{BASE}/objects", timeout=5,
                            json={"class": "LiveMT", "tenant": "liveTenantB",
                                  "properties": {"secret": "LIVE_MT_B"},
                                  "vector": [0.9, 0.8, 0.7, 0.6]})
    uuid_b = resp_b.json()["id"]

    # query scoped to tenant A must not see tenant B's data
    gql = {"query": '{ Get { LiveMT(tenant: "liveTenantA") { secret } } }'}
    r = requests.post(f"{BASE}/graphql", json=gql, timeout=5)
    assert "LIVE_MT_B" not in r.text
    assert "LIVE_MT_A" in r.text

    # fetching tenant B's object while claiming tenant A must 404
    r = requests.get(f"{BASE}/objects/LiveMT/{uuid_b}",
                      params={"tenant": "liveTenantA"}, timeout=5)
    assert r.status_code == 404

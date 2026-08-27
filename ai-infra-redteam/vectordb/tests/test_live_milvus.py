"""
Live re-verification against a running Milvus standalone container. Skips
cleanly if vectordb-milvus-standalone is not running. Start it with
scripts/run_milvus.sh first. Requires pymilvus (see vectordb/.venv or
vectordb/requirements.txt).
"""
import os

import pytest

from tests.conftest import require_live

try:
    from pymilvus import MilvusClient
    PYMILVUS_AVAILABLE = True
except ImportError:
    PYMILVUS_AVAILABLE = False

GRPC_PORT = int(os.environ.get("MILVUS_GRPC_PORT", "19530"))
URI = f"http://localhost:{GRPC_PORT}"


@pytest.fixture(autouse=True)
def _skip_if_not_running():
    require_live("vectordb-milvus-standalone", "localhost", GRPC_PORT)
    if not PYMILVUS_AVAILABLE:
        pytest.skip("pymilvus not installed - pip install pymilvus")


def test_no_auth_required():
    client = MilvusClient(uri=URI)
    # succeeds with zero credentials
    client.list_collections()


def test_databases_are_namespaced_server_side():
    client = MilvusClient(uri=URI)
    for db in ("live_db_a", "live_db_b"):
        if db not in client.list_databases():
            client.create_database(db_name=db)

    client_a = MilvusClient(uri=URI, db_name="live_db_a")
    client_b = MilvusClient(uri=URI, db_name="live_db_b")

    for c, name in ((client_a, "live_secrets"), (client_b, "live_secrets")):
        if not c.has_collection(name):
            c.create_collection(collection_name=name, dimension=4, metric_type="L2")

    desc_a = client_a.describe_collection("live_secrets")
    desc_b = client_b.describe_collection("live_secrets")
    # same collection NAME in two databases must have different internal IDs
    assert desc_a["collection_id"] != desc_b["collection_id"]

    only_in_b = "live_only_in_b"
    if not client_b.has_collection(only_in_b):
        client_b.create_collection(collection_name=only_in_b, dimension=4, metric_type="L2")

    assert client_a.has_collection(only_in_b) is False
    assert client_b.has_collection(only_in_b) is True

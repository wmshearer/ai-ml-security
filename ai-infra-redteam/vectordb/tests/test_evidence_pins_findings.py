"""
These tests require NO running container. They parse the captured evidence
files in evidence/<product>/ and assert the findings written up in
FINDINGS.md are actually backed by what was captured. This is the
re-verifiable pin: if the evidence directory is ever regenerated with
different results, these tests catch the drift.
"""
from tests.conftest import read_evidence, VECTORDB_ROOT


def test_findings_doc_exists():
    findings = VECTORDB_ROOT / "FINDINGS.md"
    assert findings.exists()
    text = findings.read_text()
    assert "ChromaDB" in text
    assert "Qdrant" in text
    assert "Weaviate" in text
    assert "Milvus" in text
    # hard constraint: no CVE IDs cited in this component's writeup
    assert "CVE-" not in text


# --- ChromaDB: default bind, no auth, tenancy exists, but NOT enforced ---

def test_chroma_default_bind_is_all_interfaces():
    text = read_evidence("chroma", "01-bind-address.txt")
    assert '"8000/tcp"' in text
    assert '"HostIp":"0.0.0.0"' in text


def test_chroma_no_auth_required_from_host():
    text = read_evidence("chroma", "03-auth-test-host.txt")
    assert "HTTP/1.1 200 OK" in text
    assert "nanosecond heartbeat" in text


def test_chroma_no_auth_required_from_peer_container():
    text = read_evidence("chroma", "04-auth-test-peer-container.txt")
    assert "HTTP/1.1 200 OK" in text


def test_chroma_has_first_class_tenant_and_database_concept():
    text = read_evidence("chroma", "05-tenancy-model.txt")
    assert '"name":"default_tenant"' in text
    assert "tenant_b" in text


def test_chroma_cross_tenant_read_succeeds_this_is_the_finding():
    """The core finding: a /get call scoped to the WRONG tenant/database path
    still returns the other tenant's real secret data. This is what
    FINDINGS.md calls 'not isolated' for Chroma."""
    text = read_evidence("chroma", "09-cross-tenant-test.txt")
    assert "TENANT_B_SECRET_VALUE_ce31d4" in text
    assert "HTTP/1.1 200 OK" in text


def test_chroma_cross_tenant_read_confirmed_even_against_nonexistent_tenant():
    text = read_evidence("chroma", "10-cross-tenant-confirm.txt")
    assert "TENANT_B_SECRET_VALUE_ce31d4" in text
    assert "nonexistent tenant/db" in text


def test_chroma_listing_itself_is_correctly_scoped():
    """Listing collections does NOT leak other tenants' collections - only
    the direct-read/query endpoints ignore tenant scoping."""
    text = read_evidence("chroma", "11-listing-leak-check.txt")
    assert "secrets_a" in text
    assert "secrets_b" not in text.split("global/admin")[0]


# --- Qdrant: no tenancy concept; flat collections isolated; payload pattern is not ---

def test_qdrant_no_auth_required():
    text = read_evidence("qdrant", "02-auth-test-host.txt")
    assert "HTTP/1.1 200 OK" in text
    assert '"version":"1.15.1"' in text


def test_qdrant_flat_collections_are_isolated_by_name():
    text = read_evidence("qdrant", "07-cross-collection-test.txt")
    assert "COLLECTION_B_SECRET_2ab7" in text
    assert "COLLECTION_A_SECRET_9f3e" in text
    # the collection_a endpoint query must never return collection_b's secret
    query_section = text.split("query collection_a with collection_b")[-1]
    assert "COLLECTION_B_SECRET_2ab7" not in query_section


def test_qdrant_multitenancy_payload_pattern_has_no_default_boundary():
    """The core finding for Qdrant: an unfiltered query against the shared
    multitenant collection returns BOTH tenants' secrets in one response."""
    text = read_evidence("qdrant", "09-multitenancy-leak-test.txt")
    assert "ALPHA_TENANT_SECRET_11a" in text
    assert "BETA_TENANT_SECRET_22b" in text


def test_qdrant_filter_correctly_restricts_when_used():
    text = read_evidence("qdrant", "10-multitenancy-with-filter-control.txt")
    assert "ALPHA_TENANT_SECRET_11a" in text
    assert "BETA_TENANT_SECRET_22b" not in text


# --- Weaviate: isolated in both flat-class and opt-in multi-tenancy modes ---

def test_weaviate_no_auth_required():
    text = read_evidence("weaviate", "02-auth-test-host.txt")
    assert "HTTP/1.1 200 OK" in text


def test_weaviate_flat_classes_default_multitenancy_disabled():
    text = read_evidence("weaviate", "04-tenancy-model-check.txt")
    assert '"enabled":false' in text


def test_weaviate_cross_class_graphql_is_isolated():
    text = read_evidence("weaviate", "06-cross-class-graphql-test.txt")
    assert "CLASSA_SECRET_7f1d" in text
    # the graphql query scoped to ClassA must not surface ClassB's secret
    graphql_section = text.split("REST test")[0]
    assert "CLASSB_SECRET_9e2a" not in graphql_section


def test_weaviate_wrong_class_uuid_fetch_returns_404():
    text = read_evidence("weaviate", "07-status-code-check.txt")
    assert "HTTP_STATUS: 404" in text


def test_weaviate_multitenancy_feature_enforces_isolation():
    text = read_evidence("weaviate", "10-multitenancy-cross-tenant-test.txt")
    assert "TENANTA_MT_SECRET_5c3f" in text
    assert "without tenant" in text  # mandatory tenant param when MT enabled
    assert "HTTP_STATUS: 404" in text  # wrong-tenant fetch rejected
    assert "TENANTB_MT_SECRET_8d1e" in text  # present only in the control fetch


def test_weaviate_tenant_names_are_enumerable_without_auth():
    """Documented caveat: isolation is real, but with no auth, tenant NAMES
    are visible to anyone who can reach the API."""
    text = read_evidence("weaviate", "11-tenant-enumeration-check.txt")
    assert "tenantA" in text
    assert "tenantB" in text


# --- Milvus: isolated via server-side (database, name) namespacing ---

def test_milvus_no_auth_required_rbac_objects_visible_without_credentials():
    text = read_evidence("milvus", "09-rbac-model-check.txt")
    assert "root" in text
    assert "admin" in text
    assert "public" in text


def test_milvus_has_first_class_database_concept():
    text = read_evidence("milvus", "03-tenancy-model-check.txt")
    assert "tenant_db_a" in text
    assert "tenant_db_b" in text


def test_milvus_same_name_collections_get_distinct_internal_ids():
    """The decisive isolation test: two databases each have a collection
    named 'secrets', but Milvus assigns them different internal IDs."""
    text = read_evidence("milvus", "07-server-side-enforcement-test.txt")
    assert "468659560957609174" in text
    assert "468659560958980318" in text


def test_milvus_has_collection_correctly_scoped_per_database():
    text = read_evidence("milvus", "07-server-side-enforcement-test.txt")
    assert "client_a.has_collection(only_in_db_b): False" in text
    assert "client_b.has_collection(only_in_db_b): True" in text

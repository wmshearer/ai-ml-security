"""
These tests require NO running container. They parse the captured evidence
files in evidence/ and assert the findings written up in FINDINGS.md are
actually backed by what was captured. This is the re-verifiable pin: if the
evidence directory is ever regenerated with different results, these tests
catch the drift.
"""
from tests.conftest import read_evidence, LATERAL_ROOT


def test_findings_doc_exists():
    findings = LATERAL_ROOT / "FINDINGS.md"
    assert findings.exists()
    text = findings.read_text()
    assert "lateral-app" in text
    assert "lateral-chroma" in text
    assert "lateral-ollama" in text
    # hard constraint: no CVE IDs cited anywhere in this component's writeup
    assert "CVE-" not in text


# --- Step 1: network reachability from the foothold, no published ports ---

def test_foothold_reaches_both_peers_without_publish_or_links():
    text = read_evidence("01-network-reachability-from-foothold.txt")
    assert "lateral-chroma" in text and "OPEN" in text
    assert "lateral-ollama" in text and "OPEN" in text


def test_foothold_container_had_no_port_publish_or_links_to_peers():
    text = read_evidence("02-app-container-has-no-port-publish-or-links-to-peers.txt")
    assert "Links: []" in text
    assert "9000/tcp" in text  # only its own port was published


def test_blind_subnet_sweep_finds_both_peers_without_dns_names():
    text = read_evidence("03-blind-subnet-sweep-no-dns-names-used.txt")
    assert "port 8000:" in text
    assert "port 11434:" in text
    # both ports must show at least one open host beyond an empty list
    assert "port 8000: open on []" not in text
    assert "port 11434: open on []" not in text


# --- Step 2: no authentication on either peer service ---

def test_chroma_no_auth_required_from_foothold():
    text = read_evidence("04-no-auth-required-from-foothold.txt")
    assert "chroma heartbeat" in text
    assert "HTTP status: 200" in text


def test_ollama_no_auth_required_from_foothold():
    text = read_evidence("04-no-auth-required-from-foothold.txt")
    assert "ollama /api/tags" in text
    assert '"models":[{"name":"tinyllama' in text


# --- Step 3: cross-tenant data read on the vector DB, from the foothold ---

def test_cross_tenant_read_returns_tenant_a_secret():
    text = read_evidence("05-cross-tenant-read-from-foothold.txt")
    assert "LATERAL_TENANT_A_SECRET_VALUE_71bd2f" in text


def test_cross_tenant_read_returns_tenant_b_secret_through_foothold_own_path():
    text = read_evidence("05-cross-tenant-read-from-foothold.txt")
    assert "LATERAL_TENANT_B_SECRET_VALUE_ae930c" in text


def test_cross_tenant_read_works_even_through_fabricated_tenant_path():
    text = read_evidence("05-cross-tenant-read-from-foothold.txt")
    fabricated_section = text.split("COMPLETELY FABRICATED")[-1]
    assert "LATERAL_TENANT_B_SECRET_VALUE_ae930c" in fabricated_section
    assert "HTTP status: 200" in fabricated_section


def test_guessed_tenant_name_listing_leaks_collection_id_with_no_auth():
    text = read_evidence("06-listing-other-tenants-still-works-because-no-auth.txt")
    assert '"name":"secrets_a"' in text
    assert "tenant_a/databases/db_a/collections -> 200" in text


def test_chroma_has_no_single_list_all_tenants_endpoint():
    """What did NOT work: no global tenant enumeration endpoint exists."""
    text = read_evidence("06-listing-other-tenants-still-works-because-no-auth.txt")
    assert "GET /api/v2/tenants -> 405" in text


# --- Step 4: inference-layer read/write/destroy, from the foothold ---

def test_ollama_list_models_works():
    text = read_evidence("07-ollama-inference-and-model-pull.txt")
    assert "list models (no auth)" in text
    assert "HTTP 200" in text


def test_ollama_arbitrary_inference_works():
    text = read_evidence("07-ollama-inference-and-model-pull.txt")
    section = text.split("arbitrary inference")[-1]
    assert "HTTP 200" in section


def test_ollama_pull_new_model_works():
    text = read_evidence("07-ollama-inference-and-model-pull.txt")
    assert "pull a NEW model" in text
    assert '"status":"success"' in text
    assert "all-minilm" in text


def test_ollama_delete_model_works():
    text = read_evidence("08-ollama-model-delete.txt")
    assert "delete a model (no auth)" in text
    assert "HTTP 200" in text
    # confirm it is actually gone afterward
    after = text.split("confirm it is gone")[-1]
    assert "all-minilm" not in after


def test_ollama_delete_nonexistent_model_correctly_404s_negative_control():
    text = read_evidence("10-additional-writes-and-negative-controls.txt")
    assert "does-not-exist-xyz" in text
    assert "HTTP 404" in text


def test_chroma_collection_delete_by_name_works_no_auth():
    text = read_evidence("10-additional-writes-and-negative-controls.txt")
    assert "delete by name -> 200" in text


def test_chroma_collection_delete_by_id_did_not_work():
    """What did NOT work: delete-by-collection-id under the tenant path 404s."""
    text = read_evidence("10-additional-writes-and-negative-controls.txt")
    assert "delete throwaway -> 404" in text


def test_planted_tenant_data_survived_the_destructive_tests():
    text = read_evidence("11-planted-data-still-intact-after-testing.txt")
    assert "secrets_a" in text
    assert "secrets_b" in text
    assert "tenant_a/db_a: 200" in text
    assert "tenant_b/db_b: 200" in text


# --- Step 5: credential recovery inside the foothold ---

def test_planted_token_recoverable_from_environment():
    text = read_evidence("09-credential-recovery-inside-foothold.txt")
    assert "INTERNAL_API_TOKEN=INTERNAL_API_TOKEN_PLANTED_9f3a7c" in text


def test_planted_token_recoverable_from_config_file():
    text = read_evidence("09-credential-recovery-inside-foothold.txt")
    section = text.split("config file written to disk")[-1]
    assert "INTERNAL_API_TOKEN_PLANTED_9f3a7c" in section


# --- Defensive conclusion: network segmentation control ---

def test_different_network_container_cannot_resolve_peers():
    """The decisive control test backing the defensive conclusion: a
    container on a DIFFERENT bridge network cannot even resolve chroma or
    ollama by name."""
    text = read_evidence("12-network-segmentation-control-different-network-blocked.txt")
    assert "lateral-chroma:8000 -> DNS FAILED" in text
    assert "lateral-ollama:11434 -> DNS FAILED" in text

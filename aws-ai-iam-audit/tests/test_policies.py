"""
Tests that pin the specific findings this project is built around.

These tests read the fetched policy JSON directly from policies/ and the
analyzer output from evidence/analyze_findings.json. They are deliberately
literal: they check for exact statement IDs (Sid) and exact structural
patterns described in the README. If AWS changes one of these managed
policies (tightens a Resource, removes a Sid, changes a tag key), these
tests should fail. That is the point: a passing test here is a claim about
what AWS's own published policy currently says, not an assumption.

Run with: .venv/bin/pytest tests/ -v
"""

import json
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
POLICIES_DIR = REPO_ROOT / "policies"
EVIDENCE_DIR = REPO_ROOT / "evidence"


def load_policy(name):
    path = POLICIES_DIR / f"{name}.json"
    if not path.exists():
        pytest.skip(f"{path} not present; run src/fetch_policies.py first")
    return json.loads(path.read_text())


def get_statement(policy_doc, sid):
    for s in policy_doc.get("Statement", []):
        if s.get("Sid") == sid:
            return s
    return None


@pytest.fixture(scope="module")
def sagemaker_full_access():
    return load_policy("AmazonSageMakerFullAccess")


@pytest.fixture(scope="module")
def bedrock_full_access():
    return load_policy("AmazonBedrockFullAccess")


@pytest.fixture(scope="module")
def analyze_findings():
    path = EVIDENCE_DIR / "analyze_findings.json"
    if not path.exists():
        pytest.skip(f"{path} not present; run src/analyze.py first")
    return json.loads(path.read_text())


# ---------------------------------------------------------------------------
# Policies exist and are the documents we think they are
# ---------------------------------------------------------------------------

REQUIRED_POLICIES = [
    "AmazonSageMakerFullAccess",
    "AmazonSageMakerReadOnly",
    "AmazonBedrockFullAccess",
    "AmazonBedrockReadOnly",
]


@pytest.mark.parametrize("policy_name", REQUIRED_POLICIES)
def test_required_policy_was_fetched(policy_name):
    doc = load_policy(policy_name)
    assert doc["Version"] == "2012-10-17"
    assert isinstance(doc["Statement"], list)
    assert len(doc["Statement"]) > 0


# ---------------------------------------------------------------------------
# AmazonSageMakerFullAccess: the wildcard PassRole
# ---------------------------------------------------------------------------

def test_sagemaker_full_access_has_wildcard_passrole(sagemaker_full_access):
    stmt = get_statement(sagemaker_full_access, "AllowPassRoleToSageMaker")
    assert stmt is not None, (
        "Sid AllowPassRoleToSageMaker not found in AmazonSageMakerFullAccess. "
        "If AWS renamed or removed this statement, the headline finding needs "
        "to be re-checked against the new policy text."
    )
    assert stmt["Effect"] == "Allow"
    assert "iam:PassRole" in stmt["Action"] if isinstance(stmt["Action"], list) else stmt["Action"] == "iam:PassRole"
    assert stmt["Resource"] == "arn:aws:iam::*:role/*"
    assert stmt["Condition"]["StringEquals"]["iam:PassedToService"] == "sagemaker.amazonaws.com"


def test_sagemaker_full_access_has_any_bucket_tagged_read(sagemaker_full_access):
    stmt = get_statement(sagemaker_full_access, "AllowS3GetObjectWithSageMakerExistingObjectTag")
    assert stmt is not None, (
        "Sid AllowS3GetObjectWithSageMakerExistingObjectTag not found. "
        "This statement is the any-bucket, tag-gated s3:GetObject grant."
    )
    assert stmt["Effect"] == "Allow"
    assert stmt["Action"] == ["s3:GetObject"]
    assert stmt["Resource"] == ["arn:aws:s3:::*"]
    assert "SageMaker" in stmt["Condition"]["StringEqualsIgnoreCase"]["s3:ExistingObjectTag/SageMaker"] or \
        stmt["Condition"]["StringEqualsIgnoreCase"]["s3:ExistingObjectTag/SageMaker"] == "true"


# ---------------------------------------------------------------------------
# AmazonBedrockFullAccess: bedrock:* and the attacker-settable tag gate
# ---------------------------------------------------------------------------

def test_bedrock_full_access_grants_bedrock_star(bedrock_full_access):
    stmt = get_statement(bedrock_full_access, "BedrockAll")
    assert stmt is not None
    assert stmt["Effect"] == "Allow"
    assert stmt["Action"] == ["bedrock:*"]
    assert stmt["Resource"] == "*"


def test_bedrock_full_access_has_tag_gated_sagemaker_endpoint_actions(bedrock_full_access):
    stmt = get_statement(bedrock_full_access, "MarketplaceModelEndpointMutatingAPIs")
    assert stmt is not None, (
        "Sid MarketplaceModelEndpointMutatingAPIs not found. This is the "
        "statement that gates SageMaker endpoint mutation on a resource tag."
    )
    condition = stmt["Condition"]["StringEquals"]
    assert condition["aws:ResourceTag/sagemaker-sdk:bedrock"] == "compatible", (
        "The tag key or required value for the Bedrock/SageMaker endpoint "
        "compatibility gate has changed from what this project documents."
    )


# ---------------------------------------------------------------------------
# Custom analyzer: pinned counts and specific statement IDs
# ---------------------------------------------------------------------------

def test_analyzer_found_expected_number_of_policies(analyze_findings):
    assert analyze_findings["policy_count"] == 8


def test_analyzer_passrole_wildcard_count(analyze_findings):
    assert analyze_findings["passrole_wildcard"]["count"] == 3
    sids = {f["sid"] for f in analyze_findings["passrole_wildcard"]["findings"]}
    assert "AllowPassRoleToSageMaker" in sids
    assert "IAMPassOperation" in sids
    assert "IAMPassOperationForForecast" in sids


def test_analyzer_passrole_wildcard_includes_sagemaker_full_access(analyze_findings):
    policies_with_wildcard_passrole = {
        f["policy"] for f in analyze_findings["passrole_wildcard"]["findings"]
    }
    assert "AmazonSageMakerFullAccess" in policies_with_wildcard_passrole


def test_analyzer_tag_gated_condition_count(analyze_findings):
    assert analyze_findings["tag_gated_condition"]["count"] == 14


def test_analyzer_tag_gated_includes_bedrock_compatible_tag(analyze_findings):
    findings = analyze_findings["tag_gated_condition"]["findings"]
    bedrock_hits = [f for f in findings if f["policy"] == "AmazonBedrockFullAccess"]
    assert len(bedrock_hits) > 0
    tag_keys = set()
    for hit in bedrock_hits:
        for tc in hit["tag_conditions"]:
            tag_keys.add(tc["key"])
    assert "aws:ResourceTag/sagemaker-sdk:bedrock" in tag_keys


def test_analyzer_any_bucket_resource_count(analyze_findings):
    assert analyze_findings["any_bucket_resource"]["count"] == 2
    sids = {f["sid"] for f in analyze_findings["any_bucket_resource"]["findings"]}
    assert "AllowS3GetObjectWithSageMakerExistingObjectTag" in sids


def test_analyzer_wildcard_resource_grant_count(analyze_findings):
    # This one is intentionally a >= check: this category (Resource == "*")
    # is broad and AWS adds statements to these policies fairly often. A
    # regression in the specific patterns above matters more than this count
    # moving by a few. Still assert a sane floor so a broken analyzer run
    # (e.g. zero policies loaded) is caught.
    assert analyze_findings["wildcard_resource_grant"]["count"] >= 30


# ---------------------------------------------------------------------------
# Sanity: no fabricated CVE or ARN strings anywhere in the evidence corpus
# ---------------------------------------------------------------------------

FORBIDDEN_STRINGS = [
    "CVE-2024-41892",  # confirmed non-existent CVE ID, must never appear
]


def test_no_fabricated_cve_ids_in_readme():
    readme = REPO_ROOT / "README.md"
    if not readme.exists():
        pytest.skip("README.md not written yet")
    text = readme.read_text()
    for bad in FORBIDDEN_STRINGS:
        assert bad not in text, f"Forbidden/fabricated identifier {bad} found in README.md"

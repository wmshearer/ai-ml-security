"""
These tests require NO running container. They parse the captured evidence
files in evidence/<product>/ and the primary-source documentation snapshots,
and assert the findings written up in FINDINGS.md are actually backed by what
was captured. If the evidence directory is ever regenerated with different
results, these tests catch the drift.
"""
from tests.conftest import read_evidence, DESIGNSTUDY_ROOT


def test_findings_doc_exists_and_covers_both_products():
    findings = DESIGNSTUDY_ROOT / "FINDINGS.md"
    assert findings.exists()
    text = findings.read_text()
    assert "Ray" in text
    assert "Triton" in text
    # only these two CVEs may be cited per the project's hard constraint
    assert "CVE-2024-41892" not in text
    for cve in ("CVE-2023-48022", "CVE-2025-23316"):
        if cve in text:
            assert cve in ("CVE-2023-48022", "CVE-2025-23316")


# --- Ray: primary-source verification ---

def test_ghsa_advisory_contains_exact_dispute_language():
    text = read_evidence("ray", "ghsa-6wgj-66m2-xxp2.json")
    assert "CVE-2023-48022" in text
    assert (
        "the vendor's position is that this report is irrelevant because "
        "Ray, as stated in its documentation, is not intended for use "
        "outside of a strictly controlled network environment"
    ) in text


def _normalize_whitespace(text: str) -> str:
    return " ".join(text.split())


def test_ray_docs_state_trusted_network_assumption():
    text = _normalize_whitespace(read_evidence("ray", "ray-security-index.txt"))
    assert (
        "Ray expects to run in a safe network environment and to act upon "
        "trusted code" in text
    )
    assert "restrict access to trusted parties only" in text


def test_ray_docs_confirm_token_auth_exists_and_is_off_by_default():
    text = read_evidence("ray", "ray-security-token-auth.txt")
    assert "Token authentication is available in Ray 2.52.0 or later" in text
    assert "Authentication is disabled by default in Ray 2.52.0" in text
    assert "RAY_AUTH_MODE=token" in text


# --- Ray: hands-on demonstration ---

def test_ray_version_confirmed():
    text = read_evidence("ray", "01-ray-version.txt")
    assert "2.58.0" in text


def test_ray_dashboard_reachable_unauthenticated():
    text = read_evidence("ray", "02-unauth-version-endpoint.txt")
    assert "HTTP_CODE:200" in text
    assert "2.58.0" in text


def test_ray_no_auth_env_vars_set_by_default():
    text = read_evidence("ray", "07-no-auth-env-var-set.txt")
    assert "no RAY_AUTH_* env vars set" in text


def test_ray_job_submission_unauthenticated_and_executes():
    """The core Ray finding: an unauthenticated POST to the job submission
    API is accepted and actually runs the entrypoint command."""
    submit = read_evidence("ray", "04-unauth-job-submit-request.txt")
    assert "HTTP_CODE:200" in submit
    assert "job_id" in submit

    status = read_evidence("ray", "05-unauth-job-status.txt")
    assert '"status": "SUCCEEDED"' in status
    assert "driver_exit_code\": 0" in status

    logs = read_evidence("ray", "06-unauth-job-logs.txt")
    assert "DESIGNSTUDY_UNAUTH_JOB_SUBMIT_TEST" in logs
    assert "\\nray\\n" in logs  # whoami output


def test_ray_authmode_rejects_unauthenticated_request():
    text = read_evidence("ray", "11-authmode-unauth-request-rejected.txt")
    assert "HTTP_CODE:401" in text
    assert "Unauthorized" in text


def test_ray_authmode_accepts_authenticated_request():
    text = read_evidence("ray", "12-authmode-authenticated-request-succeeds.txt")
    assert "HTTP_CODE:200" in text


# --- Triton: primary-source verification ---

def test_triton_docs_confirm_none_is_default_mode():
    text = read_evidence("triton", "triton-model-management.txt")
    assert "This model control mode is selected by specifying\n       --model-control-mode=none" in text
    assert "This is the default model control mode." in text


def test_triton_docs_confirm_explicit_is_opt_in():
    text = read_evidence("triton", "triton-model-management.txt")
    assert "This model control mode is enabled by specifying\n       --model-control-mode=explicit." in text


# --- Triton: hands-on demonstration ---

def test_triton_none_mode_confirmed_via_startup_log():
    text = read_evidence("triton", "01-none-mode-startup-log.txt")
    assert "MODE_NONE" in text


def test_triton_none_mode_refuses_load_and_unload():
    load = read_evidence("triton", "03-none-mode-load-endpoint-refused.txt")
    assert "HTTP_CODE:503" in load
    assert "not allowed if polling is enabled" in load

    unload = read_evidence("triton", "04-none-mode-unload-endpoint-refused.txt")
    assert "HTTP_CODE:503" in unload
    assert "not allowed if polling is enabled" in unload


def test_triton_explicit_mode_accepts_unauthenticated_load():
    """The core Triton finding: once an operator opts into
    --model-control-mode=explicit, the load endpoint accepts a request with
    zero authentication and actually loads the model."""
    load = read_evidence("triton", "06-explicit-mode-unauth-load-real-model.txt")
    assert "HTTP_CODE:200" in load

    ready = read_evidence("triton", "07-explicit-mode-model-now-ready.txt")
    assert "HTTP_CODE:200" in ready
    assert '"name":"identity_demo"' in ready


def test_triton_explicit_mode_accepts_unauthenticated_unload():
    unload = read_evidence("triton", "08-explicit-mode-unauth-unload.txt")
    assert "HTTP_CODE:200" in unload

    confirm = read_evidence("triton", "09-explicit-mode-model-unloaded-confirm.txt")
    assert "HTTP_CODE:404" in confirm
    assert "unknown model" in confirm

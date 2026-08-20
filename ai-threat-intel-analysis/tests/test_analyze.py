"""Tests for the AI-misuse case analysis.

The numbers here are the finding: AI use was a productivity aid through early 2025, then
in the second half of 2025 it appears inside malware at runtime and, in one case, running
the operation. A test locks that shift so a later change to the data cannot quietly erase
it, and locks the mapping so it cannot drift.
"""

from __future__ import annotations

from data.cases import CASES, INTEGRATION_LEVELS, Case
from src.analyze import (
    ATLAS, OWASP_2025, atlas_techniques, owasp_categories,
    integration_by_period, first_appearance, actors_by_sponsor,
)


def test_every_case_has_a_source():
    """No case is allowed without a named public source. This is the honesty guard."""
    for c in CASES:
        assert c.source, f"case for {c.actor} has no source"


def test_every_integration_level_is_valid():
    for c in CASES:
        assert c.integration in INTEGRATION_LEVELS


def test_the_shift_runtime_and_agentic_appear_only_in_late_2025():
    """The finding. Runtime and agentic AI use do not appear before 2025-H2."""
    assert first_appearance("aid") == "2024-H1"
    assert first_appearance("runtime") == "2025-H2"
    assert first_appearance("agentic") == "2025-H2"


def test_early_periods_are_all_aid():
    """Through the first half of 2025, every documented case is AI as an aid."""
    by_period = integration_by_period()
    for period in ("2024-H1", "2025-H1"):
        counts = by_period[period]
        assert counts["runtime"] == 0
        assert counts["agentic"] == 0
        assert counts["aid"] > 0


def test_late_2025_shows_runtime_and_agentic():
    counts = integration_by_period()["2025-H2"]
    assert counts["runtime"] >= 3
    assert counts["agentic"] >= 1


def test_atlas_ids_are_real_atlas_ids():
    """Every ATLAS id the mapping can emit is in the ATLAS reference table."""
    for c in CASES:
        for tid in atlas_techniques(c):
            assert tid in ATLAS, f"{tid} not a known ATLAS technique"


def test_owasp_ids_are_real_2025_ids():
    for c in CASES:
        for oid in owasp_categories(c):
            assert oid in OWASP_2025


def test_phishing_maps_to_the_phishing_technique():
    """A case that a source describes as phishing gets the ATLAS phishing id."""
    c = Case("test", "unattributed", "2024-H1", ("phishing emails",), "aid", "OPENAI_2024")
    assert "AML.T0052" in atlas_techniques(c)


def test_the_agentic_case_maps_to_excessive_agency_and_jailbreak():
    """The GTG-1002 case, the one agentic case, exhibits excessive agency (OWASP LLM06)
    and a jailbreak (ATLAS T0054), since operators used a pretext to bypass guardrails."""
    agentic = [c for c in CASES if c.integration == "agentic"]
    assert len(agentic) == 1
    c = agentic[0]
    assert "LLM06" in owasp_categories(c)
    assert "AML.T0054" in atlas_techniques(c)


def test_attribution_is_not_invented():
    """Unattributed cases stay unattributed. The mapping never guesses a sponsor."""
    sponsors = actors_by_sponsor()
    assert "unattributed" in sponsors
    # every sponsor value is one the data set, not the analysis, assigned
    allowed = {"China", "Russia", "Iran", "North Korea", "unattributed", "criminal"}
    for c in CASES:
        assert c.sponsor in allowed

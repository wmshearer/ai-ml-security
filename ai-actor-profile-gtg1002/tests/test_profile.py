"""Tests for the GTG-1002 profile in data/profile.py and src/assess.py.

These are citation-integrity and balance guards, not correctness tests in the usual
sense. The finding this project makes is that a defensive profile of a vendor's own
disclosure has to carry the vendor's admissions and the outside disputes alongside the
headline claims, or it becomes an uncredited restatement of a press release. Each test
below locks one piece of that: every claim traces to a real source, the profile cannot
lose its skepticism section, cannot lose Anthropic's own caveats, and cannot silently
pick up the misquoted "at least 4 breached" figure that circulated in press coverage.
"""

from __future__ import annotations

from data.profile import (
    ATTRIBUTION,
    CAVEATS,
    CONFIDENCE_LEVELS,
    DETECTION_RESPONSE,
    GUARDRAIL_BYPASS,
    KEY_JUDGMENTS,
    KILL_CHAIN,
    SKEPTICISM,
    TARGETING,
    TOOLING,
)
from src.assess import all_claims, claims_by_confidence, coverage_of_frameworks

ALL_CLAIM_SECTIONS = (
    KEY_JUDGMENTS,
    ATTRIBUTION,
    TARGETING,
    GUARDRAIL_BYPASS,
    TOOLING,
    DETECTION_RESPONSE,
    CAVEATS,
    SKEPTICISM,
)


def test_every_claim_has_a_non_empty_source():
    """The citation-integrity guard. A Claim with no source is just an assertion, and
    this profile's whole point is that nothing here is unsourced."""
    for claim in all_claims():
        assert claim.source, f"claim with no source: {claim.text!r}"
        assert claim.source.strip(), f"claim with blank source: {claim.text!r}"


def test_every_claim_confidence_is_in_the_allowed_set():
    """Confidence labels are a closed vocabulary. A typo'd or invented level would
    silently break the grouping in claims_by_confidence()."""
    for claim in all_claims():
        assert claim.confidence in CONFIDENCE_LEVELS, (
            f"claim {claim.text!r} has unknown confidence {claim.confidence!r}"
        )


def test_profile_includes_skepticism():
    """The profile must include the outside disputes (Beaumont, Card, the no-IOC
    critique, MITRE C0062's derivative status). Without this the profile is a one-sided
    echo of the vendor's own framing, which is exactly what this project is not meant
    to be."""
    disputed = claims_by_confidence()["disputed"]
    assert len(disputed) >= 3, "expected at least the Beaumont, Card, and no-IOC claims"
    joined = " ".join(c.text for c in disputed).lower()
    assert "beaumont" in joined
    assert "card" in joined
    assert "indicators of compromise" in joined or "iocs" in joined or "ips, domains" in joined


def test_profile_includes_anthropics_own_caveats():
    """Anthropic's own hallucination admission and visibility caveat must survive in
    the profile. Dropping them would let the 80-90% figure stand unqualified."""
    admissions = claims_by_confidence()["anthropic-admission"]
    assert len(admissions) >= 2, "expected the hallucination admission and the visibility caveat"
    joined = " ".join(c.text for c in admissions).lower()
    assert "fabricated" in joined or "hallucin" in joined
    assert "visibility" in joined or "frontier ai models" in joined


def test_kill_chain_has_exactly_six_numbered_phases_each_sourced():
    """The report describes a six-phase kill chain. This locks the count, the
    numbering, and that every phase carries its own citation."""
    assert len(KILL_CHAIN) == 6
    numbers = [phase.number for phase in KILL_CHAIN]
    assert numbers == [1, 2, 3, 4, 5, 6]
    for phase in KILL_CHAIN:
        assert phase.source, f"phase {phase.number} ({phase.name}) has no source"


def test_press_misquote_of_at_least_four_breached_is_not_asserted():
    """BleepingComputer's coverage and other press repeated 'at least 4 breached,'
    which is not the report's wording; the report says 'a handful.' This test locks
    the correction so the misquote cannot creep back into the profile."""
    for claim in all_claims():
        lowered = claim.text.lower()
        assert "at least 4" not in lowered
        assert "at least four" not in lowered


def test_coverage_of_frameworks_includes_llm_jailbreak():
    """AML.T0054 is the one ATLAS technique the source material supports in enough
    detail to map directly (the role-play pretext used to bypass guardrails)."""
    coverage = coverage_of_frameworks()
    assert "AML.T0054" in coverage
    assert coverage["AML.T0054"]


def test_all_claim_sections_are_covered_by_all_claims():
    """all_claims() must actually flatten every section, not a subset of them. If a
    section were left out of src/assess.py's CLAIM_SECTIONS this would catch it."""
    total_in_sections = sum(len(section) for section in ALL_CLAIM_SECTIONS)
    assert len(all_claims()) == total_in_sections

"""Small helpers over the GTG-1002 profile data in data/profile.py.

This does not add new intelligence. It flattens and counts the Claim records already
in the profile so the balance of the profile, how much is vendor-reported versus
disputed versus self-admitted limitation, can be measured instead of eyeballed, and so
the framework coverage can be listed in one place.

WHAT THIS IS NOT
    Not a scoring model and not a confidence calculator. It does not weigh claims
    against each other or produce a verdict on GTG-1002; it only counts and groups
    what data/profile.py already states, with its existing citations intact.
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
    Claim,
)

# Every section made up of Claim records. KILL_CHAIN is excluded here because its
# entries are Phase records, not Claim records; each Phase carries its own source
# field and is checked separately in tests.
CLAIM_SECTIONS: tuple[tuple[str, tuple[Claim, ...]], ...] = (
    ("KEY_JUDGMENTS", KEY_JUDGMENTS),
    ("ATTRIBUTION", ATTRIBUTION),
    ("TARGETING", TARGETING),
    ("GUARDRAIL_BYPASS", GUARDRAIL_BYPASS),
    ("TOOLING", TOOLING),
    ("DETECTION_RESPONSE", DETECTION_RESPONSE),
    ("CAVEATS", CAVEATS),
    ("SKEPTICISM", SKEPTICISM),
)


def all_claims() -> list[Claim]:
    """Every Claim across every section, flattened into one list."""
    claims: list[Claim] = []
    for _name, section in CLAIM_SECTIONS:
        claims.extend(section)
    return claims


def claims_by_confidence() -> dict[str, list[Claim]]:
    """All claims grouped by confidence level, one key per level in CONFIDENCE_LEVELS.

    Every level gets a key even if empty, so a missing category is visible as an
    empty list rather than a missing key.
    """
    grouped: dict[str, list[Claim]] = {level: [] for level in CONFIDENCE_LEVELS}
    for claim in all_claims():
        grouped[claim.confidence].append(claim)
    return grouped


# Framework coverage for this actor's tradecraft. Kept short and cited; a technique is
# listed only where the profile's own claims describe the matching behaviour.
FRAMEWORK_COVERAGE: dict[str, str] = {
    "AML.T0054": "LLM Jailbreak (role-play pretext and task decomposition used to "
    "bypass model guardrails). Source: MITRE ATLAS AML.T0054, Anthropic 2025 p.6, p.8.",
    "MITRE_C0062": "MITRE ATT&CK Campaign C0062, 26 associated techniques. Derivative "
    "of the Anthropic report, not an independent source; see SKEPTICISM.",
}


def coverage_of_frameworks() -> dict[str, str]:
    """The ATLAS/ATT&CK identifiers this actor's tradecraft maps to, each cited.

    Kept to what the profile's own sourced claims support. AML.T0054 is the only
    ATLAS technique the source material describes in enough detail to map directly;
    MITRE_C0062 is included as a pointer to the broader ATT&CK catalog entry, with
    its derivative status noted rather than treated as independent confirmation.
    """
    return dict(FRAMEWORK_COVERAGE)

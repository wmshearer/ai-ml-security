"""Render the GTG-1002 profile as a plain-text CTI document.

Run with: python3 scripts/render_profile.py

WHAT THIS IS NOT
    Not a new analysis. This only formats the Claim and Phase records already defined
    in data/profile.py, in the order an analyst would read them: judgments first, then
    the supporting detail, then the limits.
"""

from __future__ import annotations

import os
import sys

# Allow running as `python3 scripts/render_profile.py` from the project root without
# installing the package.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from data.profile import (
    ATTRIBUTION,
    CAVEATS,
    DETECTION_RESPONSE,
    GUARDRAIL_BYPASS,
    KEY_JUDGMENTS,
    KILL_CHAIN,
    SKEPTICISM,
    TARGETING,
    TOOLING,
    Claim,
)


def render_claim_section(title: str, claims: tuple[Claim, ...]) -> None:
    print(title)
    print("-" * len(title))
    for claim in claims:
        print(f"  - {claim.text} [{claim.source}]")
    print()


def render_kill_chain() -> None:
    title = "KILL CHAIN"
    print(title)
    print("-" * len(title))
    for phase in KILL_CHAIN:
        print(f"  Phase {phase.number}: {phase.name}")
        print(f"    AI role:    {phase.ai_role}")
        print(f"    Human role: {phase.human_role}")
        print(f"    Source:     [{phase.source}]")
    print()


def main() -> None:
    print("=" * 70)
    print("THREAT ACTOR PROFILE: GTG-1002")
    print("Anthropic's designation for an alleged AI-orchestrated cyber")
    print("espionage campaign, disclosed November 2025")
    print("=" * 70)
    print()

    render_claim_section("KEY JUDGMENTS", KEY_JUDGMENTS)
    render_claim_section("ATTRIBUTION", ATTRIBUTION)
    render_claim_section("TARGETING", TARGETING)
    render_kill_chain()
    render_claim_section("GUARDRAIL BYPASS", GUARDRAIL_BYPASS)
    render_claim_section("TOOLING", TOOLING)
    render_claim_section("DETECTION & RESPONSE", DETECTION_RESPONSE)
    render_claim_section("CAVEATS", CAVEATS)
    render_claim_section("SKEPTICISM & ANALYTIC CONFIDENCE", SKEPTICISM)

    print("This profile is built from public reporting, primarily Anthropic's own")
    print("disclosure, and foregrounds the disputed and self-admitted limits of that")
    print("disclosure rather than repeating its framing uncritically.")


if __name__ == "__main__":
    main()

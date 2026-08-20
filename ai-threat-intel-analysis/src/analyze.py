"""Map documented AI-misuse cases to frameworks and measure the 2024 to 2025 shift.

This takes the cases in data/cases.py, which come only from public threat reports, and
does three things a threat analyst does with a pile of incidents:

  1. Maps the observed behaviours to MITRE ATLAS technique IDs, so the activity is
     described in a shared taxonomy rather than free text.
  2. Maps them to the OWASP Top 10 for LLM Applications (2025), the other standard
     lens on this kind of abuse.
  3. Measures how AI integration moved over time, from a productivity aid to a runtime
     component of malware to an agent running the operation.

WHAT THIS IS NOT
    Not new intelligence. Every case is something a named public report already
    documented. This organises and measures what those reports say. Where a report did
    not attribute a state, the case is left unattributed rather than guessed.
"""

from __future__ import annotations

from collections import Counter

from data.cases import CASES, INTEGRATION_LEVELS, Case

# MITRE ATLAS techniques relevant to LLM misuse for cyber operations. IDs and names are
# from the ATLAS data release (github.com/mitre-atlas/atlas-data). Only the techniques
# the cases actually exhibit are listed.
ATLAS = {
    "AML.T0052": "Phishing",
    "AML.T0000": "Search Open Technical Databases (recon)",
    "AML.T0102": "Generate Malicious Commands",
    "AML.T0061": "LLM Prompt Self-Replication",
    "AML.T0054": "LLM Jailbreak",
    "AML.T0056": "Extract LLM System Prompt",
}

# OWASP Top 10 for LLM Applications, 2025 edition. Full list kept for reference; the
# analysis uses the ones the cases exhibit.
OWASP_2025 = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
}


def atlas_techniques(case: Case) -> set[str]:
    """The ATLAS technique IDs a case exhibits, read from what the source describes.

    Kept deliberate and conservative: a technique is assigned only when the source's
    description of the behaviour matches it, so the mapping does not overstate coverage.
    """
    ids: set[str] = set()
    text = " ".join(case.uses).lower()
    if "phishing" in text or "social-engineering" in text or "cover letter" in text:
        ids.add("AML.T0052")
    if "recon" in text or "intelligence-gathering" in text or "vulnerability research" in text:
        ids.add("AML.T0000")
    if "command" in text or "enumeration" in text or "scripts" in text:
        ids.add("AML.T0102")
    if "rewrite its own code" in text:
        ids.add("AML.T0061")
    if "guardrail" in text or "pretext" in text:
        ids.add("AML.T0054")
    if "extraction of the model" in text or "infrastructure details" in text:
        ids.add("AML.T0056")
    return ids


def owasp_categories(case: Case) -> set[str]:
    """The OWASP LLM 2025 categories a case exhibits."""
    ids: set[str] = set()
    text = " ".join(case.uses).lower()
    if "guardrail" in text or "pretext" in text:
        ids.add("LLM01")   # prompt injection / jailbreak
    if "infrastructure details" in text or "extraction of the model" in text:
        ids.add("LLM07")   # system prompt leakage
    if case.integration == "agentic":
        ids.add("LLM06")   # excessive agency
    if "news-presenter" in text or "influence" in text:
        ids.add("LLM09")   # misinformation
    return ids


def integration_by_period() -> dict[str, Counter]:
    """Count the integration level of cases in each time period.

    This is the trend. Early periods should be almost all 'aid'. Later periods should
    show 'runtime' and 'agentic' appearing, which is the shift the project measures.
    """
    out: dict[str, Counter] = {}
    for c in CASES:
        out.setdefault(c.period, Counter())[c.integration] += 1
    return out


def atlas_coverage() -> Counter:
    """How many cases exhibit each ATLAS technique."""
    out: Counter = Counter()
    for c in CASES:
        for tid in atlas_techniques(c):
            out[tid] += 1
    return out


def actors_by_sponsor() -> Counter:
    """Count distinct actors by attributed sponsor state."""
    seen: dict[str, set[str]] = {}
    for c in CASES:
        seen.setdefault(c.sponsor, set()).add(c.actor)
    return Counter({k: len(v) for k, v in seen.items()})


def first_appearance(level: str) -> str | None:
    """The earliest period an integration level appears. Orders periods as strings,
    which sorts correctly for the YYYY-Hn format used."""
    periods = sorted({c.period for c in CASES if c.integration == level})
    return periods[0] if periods else None

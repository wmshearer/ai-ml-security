"""Map three sibling projects' observed LLM-misuse behaviour onto MITRE ATLAS and
measure coverage against the matrix, tactic by tactic.

The three sources:
  aiti      ai-threat-intel-analysis, 16 documented cases from public threat reports.
            Each case's ATLAS techniques are derived here from its `uses` text with the
            same keyword rules that project uses, so the result can be rerun and checked
            against the source data in data/aiti_cases.py.
  jailbreak jailbreak-corpus-analysis, 1,405 real jailbreak prompts sorted into 10
            technique patterns. All 10 patterns are variants of one ATLAS technique,
            LLM Jailbreak (AML.T0054), so this source is single-technique by
            construction and is asserted rather than derived from a text walk.
  detector  llm-abuse-detection, a 7-rule detector for jailbreak and prompt-injection
            text. Its rule categories cover exactly two ATLAS techniques, LLM Jailbreak
            (AML.T0054) and LLM Prompt Injection (AML.T0051), so this source is also
            asserted rather than derived from a text walk.

WHAT THIS IS NOT
    Not a claim of complete AI-threat coverage. This measures what these three specific
    data sources document against ATLAS v2026.07 (16 tactics, 101 top-level techniques),
    nothing more. A gap in the map means "not present in this data," not "impossible" or
    "cannot happen." The three sources are all built from public vendor threat reports
    and public jailbreak-prompt corpora, which mostly capture an LLM used as a tool by a
    human operator. Off-platform post-compromise behaviour, and AI-native techniques
    that vendors have not yet reported on, are underrepresented here for that reason,
    not because they are rare.
"""

from __future__ import annotations

from data.aiti_cases import CASES, Case
from src import atlas

# jailbreak-corpus-analysis: every one of its 10 prompt patterns is a form of jailbreak.
JAILBREAK_CORPUS_TECHNIQUES = {"AML.T0054"}

# llm-abuse-detection: its rule categories are jailbreak detection and prompt-injection
# detection, which are exactly these two ATLAS techniques.
DETECTOR_TECHNIQUES = {"AML.T0054", "AML.T0051"}


def case_techniques(case: Case) -> set[str]:
    """The ATLAS technique ids a case exhibits, read from what the source describes.

    Mirrors ai-threat-intel-analysis's atlas_techniques(): a technique is assigned only
    when the case's own text matches it, so the mapping does not overstate what the
    source actually reported.
    """
    ids: set[str] = set()
    text = " ".join(case.uses).lower()
    if "phishing" in text or "social-engineering" in text or "cover letter" in text:
        ids.add("AML.T0052")   # Phishing
    if "recon" in text or "intelligence-gathering" in text or "vulnerability research" in text:
        ids.add("AML.T0000")   # Search Open Technical Databases
    if "command" in text or "enumeration" in text or "scripts" in text:
        ids.add("AML.T0102")   # Generate Malicious Commands
    if "rewrite its own code" in text:
        ids.add("AML.T0061")   # LLM Prompt Self-Replication
    if "guardrail" in text or "pretext" in text:
        ids.add("AML.T0054")   # LLM Jailbreak
    if "extraction of the model" in text or "infrastructure details" in text:
        ids.add("AML.T0056")   # Extract LLM System Prompt
    return ids


def covered_techniques() -> dict[str, set[str]]:
    """source name -> the ATLAS technique ids that source's data exhibits.

    The aiti set is built by walking every case in CASES through case_techniques(), not
    written by hand. The other two sources are asserted with the justification in the
    module docstring.
    """
    aiti_ids: set[str] = set()
    for case in CASES:
        aiti_ids |= case_techniques(case)
    return {
        "aiti": aiti_ids,
        "jailbreak-corpus": set(JAILBREAK_CORPUS_TECHNIQUES),
        "detector": set(DETECTOR_TECHNIQUES),
    }


def all_covered() -> set[str]:
    """The union of every technique id any of the three sources covers."""
    covered: set[str] = set()
    for ids in covered_techniques().values():
        covered |= ids
    return covered


def technique_coverage() -> dict:
    """Technique-level coverage: covered top-level techniques over all 101."""
    total = atlas.toplevel_techniques()
    covered = all_covered()
    return {
        "covered": len(covered),
        "total": len(total),
        "fraction": len(covered) / len(total),
        "covered_ids": sorted(covered),
    }


def tactic_coverage() -> dict[str, dict]:
    """Per tactic, how many of its top-level techniques are covered.

    A technique counts toward every tactic it is mapped to under technique_tactics, so a
    technique like LLM Jailbreak, which sits under both Privilege Escalation and Defense
    Evasion, is counted in both.
    """
    covered = all_covered()
    toplevel = set(atlas.toplevel_techniques())

    by_tactic_total: dict[str, set[str]] = {tid: set() for tid in atlas.tactic_order()}
    for tid in toplevel:
        for tac in atlas.tactics_of(tid):
            if tac in by_tactic_total:
                by_tactic_total[tac].add(tid)

    result: dict[str, dict] = {}
    for tac in atlas.tactic_order():
        total_ids = by_tactic_total[tac]
        covered_ids = sorted(total_ids & covered)
        total = len(total_ids)
        result[tac] = {
            "name": atlas.tactic_name(tac),
            "covered": len(covered_ids),
            "total": total,
            "fraction": (len(covered_ids) / total) if total else 0.0,
            "covered_ids": covered_ids,
        }
    return result


def tactics_touched() -> set[str]:
    """Tactic ids with at least one covered technique."""
    covered = all_covered()
    touched: set[str] = set()
    for tid in covered:
        touched |= set(atlas.tactics_of(tid))
    return touched


def gaps() -> dict[str, list]:
    """Per tactic, the uncovered top-level techniques. Readable, not exhaustive: this
    lists technique id and name so a reader can see exactly what "not covered" means for
    that tactic, not just a count."""
    covered = all_covered()
    toplevel = set(atlas.toplevel_techniques())

    by_tactic_total: dict[str, set[str]] = {tid: set() for tid in atlas.tactic_order()}
    for tid in toplevel:
        for tac in atlas.tactics_of(tid):
            if tac in by_tactic_total:
                by_tactic_total[tac].add(tid)

    result: dict[str, list] = {}
    for tac in atlas.tactic_order():
        uncovered = sorted(by_tactic_total[tac] - covered)
        result[tac] = [(tid, atlas.technique_name(tid)) for tid in uncovered]
    return result

"""
Hand-maintained lookup: garak probe_classname / PyRIT attack class -> OWASP LLM
Top 10 (2026) + MITRE ATLAS technique. This is the actual Phase 2 deliverable.

Neither tool carries this mapping natively:
- garak's `Probe.tags` field is documented as MISP-format taxonomy categories,
  not OWASP/ATLAS IDs (garak/probes/base.py, confirmed in research).
- PyRIT's `Score.score_category` is free-text content-harm taxonomy (HATE_SPEECH,
  SELF_HARM, PPI, ...), also not OWASP/ATLAS.

So this table is an external, auditable adapter the harness owns and extends as
new probes/attacks get wired up against the Phase 1 target. Keys are matched
by the normalizer via exact string match first, then prefix match (see
normalize.py) so a single entry like "garak.probes.dan" can cover a whole
probe family without enumerating every subclass.

Entries are seeded only for attack classes actually wired up in this phase
(direct injection, canary/system-prompt leakage, encoding/DAN jailbreaks via
garak; excessive agency and multi-turn escalation via PyRIT) plus the
harness-native RAG-poisoning check inherited from Phase 1's attack 3. Add a
row here before routing any new probe/attack through the harness — an
unmapped source_ref should fail loudly (see normalize.py's UNMAPPED sentinel)
rather than silently reporting an ownerless finding.
"""
from __future__ import annotations

from typing import TypedDict


class OwaspMapping(TypedDict):
    owasp_2026_id: str
    owasp_2026_name: str
    atlas_technique_id: str
    atlas_technique_name: str


# --- garak probe_classname -> mapping -------------------------------------
# Keys are the dotted classname exactly as garak's Attempt.as_dict() writes
# them into "probe_classname" (module path + class, e.g.
# "garak.probes.promptinject.HijackHateHumansMini"). A trailing "*" marks a
# prefix entry covering an entire probe module (all classes within it),
# used where every probe in that module maps to the same OWASP category.
GARAK_PROBE_MAPPING: dict[str, OwaspMapping] = {
    "garak.probes.promptinject.*": {
        "owasp_2026_id": "LLM01",
        "owasp_2026_name": "Prompt Injection",
        "atlas_technique_id": "AML.T0051.000",
        "atlas_technique_name": "LLM Prompt Injection: Direct",
    },
    "garak.probes.dan.*": {
        "owasp_2026_id": "LLM01",
        "owasp_2026_name": "Prompt Injection",
        "atlas_technique_id": "AML.T0051.000",
        "atlas_technique_name": "LLM Prompt Injection: Direct",
    },
    "garak.probes.encoding.*": {
        "owasp_2026_id": "LLM01",
        "owasp_2026_name": "Prompt Injection",
        "atlas_technique_id": "AML.T0051.000",
        "atlas_technique_name": "LLM Prompt Injection: Direct (encoded/obfuscated)",
    },
    # Corrected 2026-08-17 after independent verification against the OWASP 2026
    # source text. This was mapped to LLM08 (Hidden Context Exposure), which is
    # wrong: LLM08 covers extraction of the *system prompt / developer
    # instructions / tool schemas*. garak's leakreplay probes verbatim
    # training-data memorization, which is LLM02 Sensitive Information
    # Disclosure. A reviewer who knows the 2026 list would catch the old mapping.
    "garak.probes.leakreplay.*": {
        "owasp_2026_id": "LLM02",
        "owasp_2026_name": "Sensitive Information Disclosure",
        "atlas_technique_id": "AML.T0057",
        "atlas_technique_name": "LLM Data Leakage",
    },
}

# --- PyRIT attack class -> mapping -----------------------------------------
# Keys are the bare class name under pyrit.executor.attack.* (module path
# omitted since PyRIT does not serialize a classname string onto
# AttackResult the way garak does onto Attempt — the harness's own PyRIT
# driver code supplies this key explicitly when it constructs the attack;
# see pyrit_target.py).
PYRIT_ATTACK_MAPPING: dict[str, OwaspMapping] = {
    # Corrected 2026-08-17 after independent verification. This was mapped to
    # LLM03 Excessive Agency, which does not hold up: PromptSendingAttack is
    # PyRIT's generic single-turn *delivery* mechanism. It sends an adversarial
    # prompt; it does not by itself demonstrate that the target holds excessive
    # permissions or abuses tool invocation. Mapping the delivery vehicle to
    # LLM03 would claim evidence the run does not produce.
    #
    # The honest mapping for bare prompt-sending is LLM01. Excessive agency is
    # established by the OUTCOME — an unauthorized entry in tool_calls_made —
    # not by which attack class delivered the prompt. That is precisely what the
    # recording shim captures, and the LLM03 finding is raised by the
    # harness-native tool-call check below (see HARNESS_NATIVE_MAPPING).
    "PromptSendingAttack": {
        "owasp_2026_id": "LLM01",
        "owasp_2026_name": "Prompt Injection",
        "atlas_technique_id": "AML.T0051.000",
        "atlas_technique_name": "LLM Prompt Injection: Direct",
    },
    "CrescendoAttack": {
        "owasp_2026_id": "LLM01",
        "owasp_2026_name": "Prompt Injection",
        "atlas_technique_id": "AML.T0051.000",
        "atlas_technique_name": "LLM Prompt Injection: Direct (multi-turn escalation)",
    },
}

# --- harness-native checks (neither tool's stock probes/attacks cover this
# shape; see research item 3 — RAG-poisoning setup + retrieved_doc_ids
# scoring is application-specific and stays custom harness code, inherited
# from Phase 1's tests/run_attacks.py attack_3). Keyed by the same
# convention as the two tables above so the normalizer can treat
# "harness-native" as a third, uniform source_tool rather than a special
# case.
HARNESS_NATIVE_MAPPING: dict[str, OwaspMapping] = {
    "harness.rag_poisoning_check": {
        "owasp_2026_id": "LLM09",
        "owasp_2026_name": "Vector and Embedding Weaknesses (RAG poisoning)",
        "atlas_technique_id": "AML.T0070",
        "atlas_technique_name": "RAG Poisoning",
    },
    "harness.excessive_agency_check": {
        "owasp_2026_id": "LLM03",
        "owasp_2026_name": "Excessive Agency",
        "atlas_technique_id": "AML.T0053",
        "atlas_technique_name": "AI Agent Tool Invocation",
    },
}

# Sentinel returned by lookup() when nothing matches — deliberately visible
# in the unified schema (rather than raising) so a normalizer run over a
# large batch surfaces every gap in one pass instead of dying on the first
# unmapped probe. Callers that want strict behavior should check for this
# id explicitly (see normalize.py's strict= flag).
UNMAPPED: OwaspMapping = {
    "owasp_2026_id": "UNMAPPED",
    "owasp_2026_name": "no mapping table entry — add one to mapping.py",
    "atlas_technique_id": "UNMAPPED",
    "atlas_technique_name": "no mapping table entry — add one to mapping.py",
}


def _lookup_table(table: dict[str, OwaspMapping], key: str) -> OwaspMapping | None:
    """Exact match first, then longest-prefix match against "*"-suffixed
    module-family entries (e.g. "garak.probes.dan.*" covers
    "garak.probes.dan.Dan_11_0"). Longest-prefix wins so a more specific
    entry can be added later without a broader one shadowing it.
    """
    if key in table:
        return table[key]

    best: tuple[int, OwaspMapping] | None = None
    for table_key, mapping in table.items():
        if not table_key.endswith("*"):
            continue
        prefix = table_key[:-1]  # strip trailing "*", keep the "."
        if key.startswith(prefix):
            if best is None or len(prefix) > best[0]:
                best = (len(prefix), mapping)
    return best[1] if best else None


def lookup_garak(probe_classname: str) -> OwaspMapping | None:
    return _lookup_table(GARAK_PROBE_MAPPING, probe_classname)


def lookup_pyrit(attack_class: str) -> OwaspMapping | None:
    return _lookup_table(PYRIT_ATTACK_MAPPING, attack_class)


def lookup_harness_native(check_name: str) -> OwaspMapping | None:
    return _lookup_table(HARNESS_NATIVE_MAPPING, check_name)

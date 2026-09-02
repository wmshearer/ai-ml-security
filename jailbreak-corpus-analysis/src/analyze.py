"""Classify jailbreak prompts by technique and map the techniques to frameworks.

Two papers are involved, and keeping them straight matters. The CORPUS is from Shen et
al., "Do Anything Now", CCS 2024 (the 1,405 prompts). The TAXONOMY applied here is from a
separate, earlier paper, Liu et al., "Jailbreaking ChatGPT via Prompt Engineering: An
Empirical Study" (arXiv:2305.13860), which defines 3 TYPES built from 10 PATTERNS:

  Pretending           Character Roleplay, Assumed Responsibility, Research Experiment
  Attention Shifting    Text Continuation, Logical Reasoning, Program Execution, Translation
  Privilege Escalation  Superior Model, Sudo Mode, Simulate Jailbreaking (DAN, dev mode, etc.)

Shen et al. does its own categorization by graph community detection, not this taxonomy,
so the "Pretending dominates" result below is a finding of THIS analysis (Liu's taxonomy
applied to Shen's corpus), not a claim either paper makes. Liu's per-prompt labels are not
published in a machine-readable form for this corpus, so this module reconstructs the
pattern classifier as a set of keyword/regex rules over the real prompt text. A prompt can
match more than one pattern, or none. Each pattern is mapped to a MITRE ATLAS technique and
an OWASP LLM Top 10 (2025) category, kept conservative so the mapping does not overstate
what a keyword match actually proves.

WHAT THIS IS NOT
    Not a new attack taxonomy and not a way to generate new jailbreaks. This applies
    Liu et al.'s published taxonomy to Shen et al.'s public corpus, for the purpose
    of counting and classifying what technique families are already out there. The
    output is counts and pattern names, never prompt text.
"""

from __future__ import annotations

import re
from collections import Counter

from data.corpus import Prompt

# MITRE ATLAS techniques relevant to jailbreak prompts. IDs and names are from the
# ATLAS data release (github.com/mitre-atlas/atlas-data). AML.T0054 is the one this
# module actually emits; AML.T0051 is kept as reference since jailbreak prompts are a
# form of prompt injection, even though the classifier below does not distinguish
# injection from jailbreak at the pattern level.
ATLAS = {
    "AML.T0054": "LLM Jailbreak",
    "AML.T0051": "LLM Prompt Injection",
}

# OWASP Top 10 for LLM Applications, 2025 edition. Full list kept for reference; the
# analysis uses the ones the patterns exhibit.
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

# Liu et al.'s 3 types, holding their 10 patterns. This is the taxonomy structure; the
# PATTERNS table below assigns each pattern name to one of these types.
TYPES = ("Pretending", "Attention Shifting", "Privilege Escalation")

# pattern_name -> (type, compiled regex). Regexes are case-insensitive and tuned
# against the pattern frequencies scanned over this corpus, so counts land in a sensible
# ballpark even though the per-prompt labels themselves are reconstructed here, not
# copied from Liu et al.
PATTERNS: dict[str, tuple[str, re.Pattern[str]]] = {
    "roleplay-character": (
        "Pretending",
        re.compile(
            r"\byou are (?:now )?(?:going to (?:be|act as|pretend)|a|an)\b"
            r"|\bact as\b"
            r"|\bpretend (?:to be|you are)\b"
            r"|\brole.?play\b"
            r"|\bstay in character\b"
            r"|\bin this fictional\b"
            r"|\bcharacter of\b"
            r"|\bfrom now on you (?:are|will be)\b"
            r"|\byour (?:new )?name is\b"
            r"|\byou will pretend\b"
            r"|\byou will play the role\b"
            r"|\bpersona\b",
            re.I,
        ),
    ),
    "hypothetical-research": (
        "Pretending",
        re.compile(
            r"\bhypothetical(?:ly)?\b"
            r"|\bresearch (?:purposes|experiment|study)\b"
            r"|\bfor (?:educational|academic|research) purposes\b"
            r"|\bfictional world\b"
            r"|\bthought experiment\b"
            r"|\bimagine (?:that|a|you)\b"
            r"|\bin this (?:scenario|story|world)\b"
            r"|\bsuppose\b"
            r"|\bwhat if\b"
            r"|\bexperiment\b"
            r"|\bsimulation\b",
            re.I,
        ),
    ),
    "text-continuation": (
        "Attention Shifting",
        re.compile(r"\bcontinue\b|\bcontinuation\b", re.I),
    ),
    "translation": (
        "Attention Shifting",
        re.compile(r"\btranslat(?:e|ion|ing|or)\b", re.I),
    ),
    "no-restrictions": (
        "Privilege Escalation",
        re.compile(
            r"\bno restrictions\b"
            r"|\bwithout (?:any )?restrictions\b"
            r"|\bno rules\b"
            r"|\bwithout limitations\b"
            r"|\bno limits\b"
            r"|\bno filters?\b"
            r"|\bunrestricted\b"
            r"|\bno boundaries\b",
            re.I,
        ),
    ),
    "dan-persona": (
        "Privilege Escalation",
        re.compile(r"\bDAN\b|\bdo anything now\b", re.I),
    ),
    "dev-mode": (
        "Privilege Escalation",
        re.compile(r"\bdeveloper mode\b|\bdev mode\b|\bdebug mode\b|\bmaintenance mode\b", re.I),
    ),
    "sudo-superior-model": (
        "Privilege Escalation",
        re.compile(
            r"\bsudo\b"
            r"|\bsuperior model\b"
            r"|\broot (?:access|mode)\b"
            r"|\badmin(?:istrator)? (?:mode|access|privileges?)\b"
            r"|\belevated privileges?\b",
            re.I,
        ),
    ),
    "opposite-antigpt": (
        "Privilege Escalation",
        re.compile(
            r"\bopposite (?:day|mode|of|from|to|bot)\b"
            r"|\bexact opposite\b"
            r"|\bAntiGPT\b"
            r"|\bcomplete opposite\b"
            r"|\bsays? the opposite\b"
            r"|\bopposite (?:personality|ethical|way)\b",
            re.I,
        ),
    ),
    "token-smuggling-encode": (
        "Attention Shifting",
        re.compile(
            r"\bbase64\b"
            r"|\bROT13\b"
            r"|\bencod(?:e|ed|ing|er)\b"
            r"|\bcipher\b"
            r"|\bleetspeak\b"
            r"|\bl33t\b"
            r"|\bmorse code\b"
            r"|\bbinary\b"
            r"|\bencrypt(?:ed|ion)?\b"
            r"|\basterisks?\b"
            r"|\bobfuscat\w*\b"
            r"|\bspecial characters?\b",
            re.I,
        ),
    ),
    "ignore-instructions": (
        "Privilege Escalation",
        re.compile(
            r"\bignore (?:all )?(?:previous|prior|above|your) (?:instructions|rules|guidelines|programming)\b"
            r"|\bdisregard (?:previous|prior|all) instructions\b",
            re.I,
        ),
    ),
}


def classify(prompt: Prompt) -> set[str]:
    """The set of pattern names a prompt's text matches. May be empty or several."""
    matched = set()
    for name, (_type, rx) in PATTERNS.items():
        if rx.search(prompt.text):
            matched.add(name)
    return matched


def type_of(pattern_name: str) -> str:
    """The taxonomy TYPE (from Liu et al.) a given pattern belongs to."""
    return PATTERNS[pattern_name][0]


def pattern_distribution(corpus: tuple[Prompt, ...]) -> Counter:
    """How many prompts match each pattern."""
    counts: Counter = Counter()
    for p in corpus:
        for name in classify(p):
            counts[name] += 1
    return counts


def type_distribution(corpus: tuple[Prompt, ...]) -> Counter:
    """How many prompts hit each TYPE. A prompt counts once per distinct type it hits,
    even if it matches several patterns within that type."""
    counts: Counter = Counter()
    for p in corpus:
        types_hit = {type_of(name) for name in classify(p)}
        for t in types_hit:
            counts[t] += 1
    return counts


def platform_distribution(corpus: tuple[Prompt, ...]) -> Counter:
    """How many prompts came from each platform."""
    return Counter(p.platform for p in corpus)


def unclassified_count(corpus: tuple[Prompt, ...]) -> int:
    """Prompts that match zero patterns. The reconstructed classifier is a set of
    regexes standing in for Liu et al.'s taxonomy, not their own per-prompt labelling,
    so it will not catch everything. This number says how much of the corpus the
    classifier leaves unaccounted for."""
    return sum(1 for p in corpus if not classify(p))


def atlas_for_pattern(pattern_name: str) -> set[str]:
    """ATLAS technique IDs a pattern implies. Kept conservative: every jailbreak
    pattern is, at minimum, an instance of LLM Jailbreak (AML.T0054), since that is
    exactly what the corpus is a collection of."""
    return {"AML.T0054"}


def owasp_for_pattern(pattern_name: str) -> set[str]:
    """OWASP LLM Top 10 (2025) categories a pattern implies. Every jailbreak pattern
    is, at minimum, a form of prompt injection (LLM01): the prompt is engineered to
    override the model's intended behaviour."""
    return {"LLM01"}

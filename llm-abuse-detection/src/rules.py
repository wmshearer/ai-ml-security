"""Local regex/keyword rules that flag likely jailbreak or prompt-injection text.

Seven categories, each grounded in phrasings seen in real jailbreak prompts (the
verazuo/jailbreak_llms corpus) and in the heuristics used by existing open detectors:
instruction-override, persona-injection, leak-extraction, delimiter-attack,
encoding-obfuscation, privilege-escalation, hypothetical-framing. A prompt is flagged
if ANY rule fires (logical OR). This mirrors the "heuristics/signature" layer found in
Vigil, Rebuff, and LLM Guard, which all run cheap local pattern checks ahead of (or
instead of) a model call.

WHAT THIS IS NOT
    Not a complete defense and not a substitute for a model-based or embedding-based
    classifier. Regex matches surface phrasing, nothing else. It is defeated by
    paraphrase, translation, novel wording, or by encoding the attack text itself
    (base64, unicode tricks) so the trigger words never appear in plaintext. Real
    systems layer this fast local pass with semantic similarity search and/or an
    LLM-based judge; this module is only the first, cheapest layer of that stack.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# OWASP Top 10 for LLM Applications, 2025 edition. LLM01 is the category this whole
# module targets: prompt injection (which subsumes jailbreak attempts that try to
# override the model's original instructions). Confirmed from the primary source
# (owasp.org/www-project-top-10-for-large-language-model-applications).
OWASP_2025 = {
    "LLM01": "Prompt Injection",
}

# MITRE ATLAS techniques these rules are meant to catch. IDs and names confirmed
# against the ATLAS data release (raw ATLAS.yaml at github.com/mitre-atlas/atlas-data):
# AML.T0054 sits under Privilege Escalation and Defense Evasion; AML.T0051 under Execution.
FRAMEWORKS = {
    "OWASP_LLM01": "Prompt Injection",
    "ATLAS_AML.T0054": "LLM Jailbreak",
    "ATLAS_AML.T0051": "LLM Prompt Injection",
}


@dataclass(frozen=True)
class Rule:
    name: str
    category: str
    pattern: re.Pattern[str]
    description: str


RULES: tuple[Rule, ...] = (
    Rule(
        name="instruction-override",
        category="instruction-override",
        pattern=re.compile(
            r"\bignore (?:all |any )?(?:the )?(?:previous|prior|above|earlier|your) "
            r"(?:instructions?|rules?|guidelines?|prompts?|programming)\b"
            r"|\bdisregard (?:all |any )?(?:previous|prior|above|your) "
            r"(?:instructions?|rules?|guidelines?)\b"
            r"|\bforget (?:everything|all)(?: (?:above|before|prior))?\b"
            r"|\bforget your (?:instructions?|rules?|training)\b",
            re.I,
        ),
        description="Explicit attempt to override or discard prior instructions.",
    ),
    Rule(
        name="persona-injection",
        category="persona-injection",
        pattern=re.compile(
            # The named-persona acronyms (DAN, STAN, AIM, DUDE) are kept case-sensitive
            # with (?-i:...) so they match the jailbreak personas, which are always upper
            # case, and do not fire on the ordinary lower-case words "aim", "stan", or
            # "dude". An earlier version matched "aim" inside a benign paper abstract.
            r"\byou are (?:now )?DAN\b"
            r"|\bdo anything now\b"
            r"|\bact as (?:an? )?(?:unrestricted|unfiltered|unlimited|uncensored|jailbroken)\b"
            r"|\byou are now (?:a|an)\b"
            r"|(?-i:\bSTAN\b|\bAIM\b|\bDUDE\b)"
            r"|\bdeveloper mode\b"
            r"|\b(?:completely |fully )?amoral\b"
            r"|\bAI named\b"
            r"|\bnever refuses?\b"
            r"|\bnever break character\b"
            r"|\bstays? in character\b"
            r"|\bin character\b|\broleplay\b|\brole.?play\b"
            r"|\bact as an?\b"
            r"|\bfrom now on you\b",
            re.I,
        ),
        description="Framing the model as an alternate persona or roleplay character to escape its default behavior.",
    ),
    Rule(
        name="leak-extraction",
        category="leak-extraction",
        pattern=re.compile(
            r"\brepeat the words? above\b"
            r"|\boutput your system prompt\b"
            r"|\bwhat are your instructions\b"
            r"|\breveal your (?:prompt|instructions|system prompt)\b"
            r"|\bprint your instructions\b"
            r"|\bshow me your (?:system )?prompt\b"
            r"|\bprint the (?:above|preceding) text\b",
            re.I,
        ),
        description="Asking the model to disclose its own system prompt or instructions.",
    ),
    Rule(
        name="delimiter-attack",
        category="delimiter-attack",
        pattern=re.compile(
            r"\[SYSTEM\]"
            r"|^###"
            r"|<\|im_start\|>|<\|im_end\|>"
            r"|</s>"
            r"|^\s*System:\s"
            r"|<system>|</system>",
            re.I | re.M,
        ),
        description="Fake instruction-boundary tokens simulating a new system/prompt context.",
    ),
    Rule(
        name="encoding-obfuscation",
        category="encoding-obfuscation",
        pattern=re.compile(
            r"\bbase ?64\b"
            r"|\bROT13\b"
            r"|\bleetspeak\b|\bl33t\b"
            r"|\bmorse code\b"
            r"|\bbinary code\b"
            r"|\bcipher\b"
            r"|\bdecode this\b|\bencode this\b"
            r"|\bencrypt(?:ed|ion)?\b",
            re.I,
        ),
        description="References to encoding/ciphers used to smuggle content past a filter.",
    ),
    Rule(
        name="privilege-escalation",
        category="privilege-escalation",
        pattern=re.compile(
            r"\bjailbreak(?:ing)? mode\b"
            r"|\bunlocked mode\b"
            r"|\bsudo\b"
            r"|\broot access\b"
            r"|\bno (?:restrictions|filters|limits|limitations|boundaries|rules)\b"
            r"|\bwithout any restrictions\b"
            r"|\bunrestricted (?:mode|version|AI|model)\b"
            r"|\buncensored\b"
            r"|\bunfiltered\b"
            r"|\bwithout any warnings?\b"
            r"|\bwithout (?:regards? for|any regard for) (?:legality|ethicality|morality)\b"
            r"|\bno (?:moral|morals|censorship|moderation)s?\b"
            r"|\bnot bound by any\b"
            r"|\byou have no\b"
            r"|\bno matter what\b"
            r"|\byou must obey\b|\bmust comply\b",
            re.I,
        ),
        description="Claims of an elevated, unfiltered, or rule-free operating mode with no limits on compliance.",
    ),
    Rule(
        name="hypothetical-framing",
        category="hypothetical-framing",
        pattern=re.compile(
            r"\bhypothetically\b"
            r"|\bfor a (?:novel|story|screenplay) (?:I'?m writing|I am writing)\b"
            r"|\bin a fictional world where\b"
            r"|\bimagine you are\b"
            r"|\bpretend that\b|\bpretend to be\b"
            r"|\bfor research purposes\b",
            re.I,
        ),
        description="Wrapping a request in a hypothetical/fictional/research frame to bypass refusal.",
    ),
)


def matched_rules(text: str) -> set[str]:
    """The set of rule names whose pattern fires somewhere in text."""
    return {rule.name for rule in RULES if rule.pattern.search(text)}


def is_flagged(text: str) -> bool:
    """True if any rule fires on text (logical OR across all rules)."""
    return any(rule.pattern.search(text) for rule in RULES)

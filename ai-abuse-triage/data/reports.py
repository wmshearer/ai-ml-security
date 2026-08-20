"""Corpus of AbuseReport records for the triage scorer.

Positives (`positives()`, 16 records, `synthetic=False`): mapped one-to-one
from the 16 real, publicly documented `Case` records in the sibling
ai-threat-intel-analysis project's `data/cases.py`. Every positive here
traces to a named threat-intel report (OpenAI, Microsoft, Google, or
Anthropic) via that project's own source citations. Nothing about the
mapped category, integration level, or scale is invented; category is
derived from keyword matching against the case's own `uses` text, integration
is copied directly from the case's `integration` field, evidence_source is
`multi_source` because every one of these cases comes from a named vendor
threat report (not a single unverified tip), and scale is parsed out of the
`uses` text where a number is stated (only GTG-1002 states one, ~30 targets)
and otherwise left at a conservative default of 1.

Negatives (`negatives()`, `synthetic=True`): CONSTRUCTED low-priority
reports, not real incidents. Modeled on the kind of noise a real AI-abuse
report queue receives: spam complaints, vague unsubstantiated user tips,
false alarms, and low-severity ToS gripes. Every one is marked
`synthetic=True` and `is_actionable=False`. These exist only so the scorer
has a negative class to be measured against (precision/recall/PR-AUC/MCC are
undefined without one), mirroring how the sibling llm-abuse-detection
project pairs real jailbreak transcripts with a benign set. They are never
to be read, reported, or logged as real reports; every consumer of this
module (see src/evaluate.py, scripts/run_triage.py) surfaces `synthetic` so
this stays visible downstream.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

from src.schema import AbuseReport

# The sibling project also has a top-level `data` package, which would
# collide with this project's own `data` package under a plain sys.path
# import (`from data.cases import CASES` would resolve to whichever `data`
# package sys.path finds first, not necessarily the right one). Loading the
# sibling's cases.py by explicit file path avoids that collision entirely.
# The module is registered in sys.modules under a distinct name
# (`aiti_cases`) before exec so `@dataclass` can resolve `cls.__module__`
# during class creation (dataclasses needs the module present in
# sys.modules while its class body executes).
_AITI_CASES_PATH = Path("/home/kali/director/projects/ai-threat-intel-analysis/data/cases.py")


def _load_aiti_cases():
    spec = importlib.util.spec_from_file_location("aiti_cases", _AITI_CASES_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["aiti_cases"] = module
    spec.loader.exec_module(module)
    return module


CASES = _load_aiti_cases().CASES

# ---------------------------------------------------------------------------
# Category derivation from a Case's `uses` text
# ---------------------------------------------------------------------------

# Checked in order; first match wins. Order matters: state-actor espionage/
# agentic-operation language is checked before the broader malware-dev
# keywords so an agentic espionage campaign (GTG-1002) lands in
# state_cyber_ops rather than malware_dev, and runtime malware-code keywords
# are checked before generic phishing/scam language so a case that has both
# (e.g. mentions phishing AND malware) lands in the more severe category.
_CATEGORY_KEYWORDS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("state_cyber_ops", ("espionage", "agent ran", "exploit development",
                          "credential harvesting", "exfiltration")),
    ("malware_dev", ("malware", "rewrite its own code", "ransomware",
                      "remote access trojan", "credential-stealer",
                      "crypter", "infostealer", "generate commands",
                      "generate enumeration")),
    ("influence_op", ("influence operation", "news-presenter")),
    ("scam_fraud", ("phishing", "resumes and job applications",
                     "laptop-farm", "cover letters")),
)


def _derive_category(uses: tuple[str, ...]) -> str:
    text = " ".join(uses).lower()
    for category, keywords in _CATEGORY_KEYWORDS:
        if any(kw in text for kw in keywords):
            return category
    # Fallback for cases that describe only reconnaissance/tooling support
    # with no clearer signal (e.g. Forest Blizzard, Salmon Typhoon, APT41):
    # still state-linked cyber activity, so state_cyber_ops rather than the
    # catch-all spam_other bucket.
    return "state_cyber_ops"


# ---------------------------------------------------------------------------
# Scale derivation from a Case's `uses` text
# ---------------------------------------------------------------------------

_DEFAULT_SCALE = 1

# Only GTG-1002's uses text states an explicit target count ("about 30
# targets"). Mapping is done by explicit lookup rather than free-text number
# parsing, since regex-extracting the first integer out of arbitrary prose
# text is unreliable and would silently misparse phrases like "80 to 90
# percent" as a target count.
_SCALE_OVERRIDES: dict[str, int] = {
    "GTG-1002": 30,
}


def _derive_scale(actor: str) -> int:
    return _SCALE_OVERRIDES.get(actor, _DEFAULT_SCALE)


def _case_to_report(idx: int, case) -> AbuseReport:
    return AbuseReport(
        id=f"real-{idx:02d}",
        subject_id=case.actor,
        alleged_category=_derive_category(case.uses),
        integration_level=case.integration,
        evidence_source="multi_source",
        scale=_derive_scale(case.actor),
        reported_period=case.period,
        is_actionable=True,
        synthetic=False,
        raw=f"{case.actor} ({case.sponsor}): " + "; ".join(case.uses) + f" [source: {case.source}]",
    )


def positives() -> list[AbuseReport]:
    """The 16 real documented cases, mapped from ai-threat-intel-analysis's
    CASES. All synthetic=False, is_actionable=True.
    """
    return [_case_to_report(i, case) for i, case in enumerate(CASES)]


# ---------------------------------------------------------------------------
# Constructed negatives (synthetic=True, is_actionable=False)
#
# These are NOT real incidents. Text is written to sound like plausible
# report-queue noise while being unmistakably low-priority: no corroborating
# evidence, no real scale, generic/incoherent complaints, or reports whose
# alleged category is serious but whose evidence is a single uncorroborated
# user_report with no other signal.
# ---------------------------------------------------------------------------

_NEGATIVE_SPECS: tuple[tuple[str, str, str, str, int, str, str], ...] = (
    # (subject_id, category, integration, evidence, scale, period, raw)
    ("user-88213", "spam_other", "aid", "user_report", 1, "2025-H2",
     "User reports the chatbot 'said something weird' but declines to give any example or transcript."),
    ("user-10442", "spam_other", "aid", "user_report", 1, "2025-H2",
     "Anonymous tip claims 'my competitor is definitely using AI to cheat' with no further detail."),
    ("user-55810", "spam_other", "aid", "user_report", 1, "2025-H1",
     "Complaint that the model's free tier has usage limits, filed under the abuse-report form by mistake."),
    ("user-90021", "spam_other", "aid", "user_report", 1, "2025-H1",
     "Report alleges the assistant 'sounds sarcastic sometimes', requests a policy investigation."),
    ("user-31207", "spam_other", "aid", "user_report", 2, "2025-H2",
     "Duplicate filing of a billing dispute, submitted three times to the abuse queue instead of support."),
    ("user-77654", "spam_other", "aid", "user_report", 1, "2024-H2",
     "Vague claim that 'someone somewhere' is using the API for something bad, no account or evidence given."),
    ("user-40399", "scam_fraud", "aid", "user_report", 1, "2025-H1",
     "Single user reports receiving one unsolicited marketing email that merely mentions AI in the copy."),
    ("user-61255", "scam_fraud", "aid", "user_report", 1, "2024-H2",
     "Report alleges a scam website 'might' use AI-generated text, based on the writing style alone, no other evidence."),
    ("user-20874", "influence_op", "aid", "user_report", 1, "2025-H1",
     "User speculates a social-media account is AI-influence-operation-linked because its posts 'feel off', no corroboration."),
    ("user-83341", "influence_op", "aid", "user_report", 3, "2024-H2",
     "Forwarded chain message alleging a foreign influence campaign; contains no verifiable claims about AI use."),
    ("user-17708", "malware_dev", "aid", "user_report", 1, "2025-H2",
     "User asserts an unnamed 'hacker group' is 'probably' using AI to write malware, offers no artifact or source."),
    ("user-64920", "malware_dev", "aid", "user_report", 1, "2024-H1",
     "Report cites a rumor from an online forum about AI-assisted malware with no link, sample, or named actor."),
    ("user-29556", "state_cyber_ops", "aid", "user_report", 1, "2025-H1",
     "Anonymous submission alleges a nation-state actor is involved, based solely on the submitter's guess."),
    ("user-73104", "scam_fraud", "aid", "osint", 4, "2025-H2",
     "Open-source scan flags a handful of low-quality spam accounts using generic AI-written marketing copy; no fraud confirmed."),
    ("user-52210", "spam_other", "aid", "automated_signal", 5, "2025-H1",
     "Automated content filter flagged repetitive promotional messages as policy noise; manual review found no abuse."),
    ("user-38867", "scam_fraud", "aid", "osint", 2, "2024-H2",
     "OSINT sweep surfaces a low-traffic phishing page with boilerplate AI-generated copy; no victims or campaign confirmed."),
    ("user-95412", "spam_other", "aid", "user_report", 1, "2025-H2",
     "User reports being 'annoyed' by an AI-generated auto-reply bot, requests it be banned."),
    ("user-46688", "malware_dev", "aid", "osint", 1, "2025-H1",
     "OSINT note mentions a GitHub repo that references an LLM API in its README; no malicious functionality identified."),
)


def negatives() -> list[AbuseReport]:
    """~16-20 constructed low-priority reports. NOT real incidents. All
    synthetic=True, is_actionable=False. See module docstring.
    """
    reports = []
    for i, (subject_id, category, integration, evidence, scale, period, raw) in enumerate(_NEGATIVE_SPECS):
        reports.append(
            AbuseReport(
                id=f"synthetic-{i:02d}",
                subject_id=subject_id,
                alleged_category=category,
                integration_level=integration,
                evidence_source=evidence,
                scale=scale,
                reported_period=period,
                is_actionable=False,
                synthetic=True,
                raw=raw,
            )
        )
    return reports


def all_reports() -> list[AbuseReport]:
    """Positives (16 real cases) + negatives (constructed low-priority
    reports)."""
    return positives() + negatives()

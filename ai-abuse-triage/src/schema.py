"""Data model for AI-abuse triage reports.

An `AbuseReport` is a report that someone is misusing an AI system: running a
jailbreak-for-hire service, using a model to develop malware, running an
AI-assisted influence operation, using a model in a scam, or something
lower-priority (a spam complaint, a vague unsubstantiated tip, ordinary
policy noise). The triage scorer in `src/triage.py` reads these records and
produces a priority score so a reviewer knows what to look at first.

Two kinds of records populate the corpus in `data/reports.py`:

  - Positives (`synthetic=False`): derived from the 16 real, publicly
    documented cases in the sibling ai-threat-intel-analysis project's
    `data/cases.py`. Each is a real named threat actor's misuse of an AI
    model as described in a named vendor report (OpenAI, Microsoft, Google,
    Anthropic).

  - Negatives (`synthetic=True`): constructed low-priority reports (spam
    complaints, vague user tips, low-severity ToS gripes, false alarms).
    These are NOT real incidents. They exist purely so the scorer has a
    negative class to be measured against, precision, recall, PR-AUC, and
    MCC are all undefined without one. `synthetic=True` marks every one of
    them, in this schema and everywhere downstream, so a constructed report
    is never mistaken for or presented as a real one.
"""

from __future__ import annotations

from dataclasses import dataclass

ALLOWED_CATEGORIES = (
    "state_cyber_ops",
    "malware_dev",
    "influence_op",
    "scam_fraud",
    "csam_adjacent",
    "spam_other",
)

ALLOWED_INTEGRATION_LEVELS = ("aid", "runtime", "agentic")

ALLOWED_EVIDENCE_SOURCES = (
    "multi_source",
    "automated_signal",
    "osint",
    "user_report",
)


def validate_category(value: str) -> None:
    if value not in ALLOWED_CATEGORIES:
        raise ValueError(f"alleged_category {value!r} not in {ALLOWED_CATEGORIES}")


def validate_integration(value: str) -> None:
    if value not in ALLOWED_INTEGRATION_LEVELS:
        raise ValueError(f"integration_level {value!r} not in {ALLOWED_INTEGRATION_LEVELS}")


def validate_evidence(value: str) -> None:
    if value not in ALLOWED_EVIDENCE_SOURCES:
        raise ValueError(f"evidence_source {value!r} not in {ALLOWED_EVIDENCE_SOURCES}")


@dataclass(frozen=True)
class AbuseReport:
    """One report of alleged AI misuse, normalized to a fixed shape.

    `is_actionable` is ground truth (whether this is, in fact, a real
    priority case worth escalating) and must never be read by the scorer in
    `src/triage.py`, it exists only for evaluation in `src/evaluate.py`.

    `synthetic` marks whether this record was constructed for the negative
    class (True) or derived from a real documented case (False). This field
    is purely descriptive/provenance metadata, not a scoring input.
    """

    id: str
    subject_id: str
    alleged_category: str
    integration_level: str
    evidence_source: str
    scale: int
    reported_period: str
    is_actionable: bool
    synthetic: bool
    raw: str

    def __post_init__(self) -> None:
        validate_category(self.alleged_category)
        validate_integration(self.integration_level)
        validate_evidence(self.evidence_source)
        if self.scale < 0:
            raise ValueError(f"scale must be >= 0, got {self.scale}")
        if not self.id:
            raise ValueError("id must be non-empty")

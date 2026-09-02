"""Ties the triage scorer to the reused metrics module.

This is where the reuse pays off: `priority_score` (a rule-based, purely
domain-specific composite) is ranked and measured with the same rigorous
metric set the sibling ai-triage-engine project used for security alerts
(MCC and PR-AUC as headline metrics, ROC-AUC secondary, plain accuracy
never standalone, Wilson interval on precision instead of a Wald
approximation).

`is_actionable` is used here, and only here, as ground truth. Nothing in
`src/triage.py` reads it; this module is the evaluation boundary.
"""

from __future__ import annotations

from data.reports import all_reports
from src.metrics import (
    ConfusionCounts,
    confusion_counts,
    accuracy,
    balanced_accuracy,
    f1,
    mcc,
    precision,
    pr_auc,
    recall,
    roc_auc,
    wilson_interval,
)
from src.schema import AbuseReport
from src.triage import priority_score, triage

# A predicted-positive is "not dismissed" (triage() returns "review" or
# "escalate") per the scorer's own 3-way triage collapse
# (src/triage.DISMISS_MAX / REVIEW_MAX), not a separate ad hoc threshold.
# "dismiss" is the action that means a reviewer never looks at the report at
# all, so precision/recall here measure exactly the question a triage queue
# cares about: does the scorer correctly decide what a reviewer sees versus
# what gets auto-dismissed.
_DISMISS = "dismiss"


def evaluate() -> dict:
    """Score every report in the corpus, evaluate against is_actionable
    ground truth, and return the full metric set.

    Continuous score: `priority_score`, recency-anchored to the newest
    reported_period across the whole corpus.
    Binary prediction: True iff `triage(report) != "dismiss"` (i.e. the
    scorer puts it in front of a reviewer, either as "review" or
    "escalate").
    Ground truth: `report.is_actionable`.
    """
    reports: list[AbuseReport] = all_reports()
    max_period = max(r.reported_period for r in reports)

    scores = [priority_score(r, max_period=max_period) for r in reports]
    preds = [triage(r, max_period=max_period) != _DISMISS for r in reports]
    truth = [r.is_actionable for r in reports]

    c: ConfusionCounts = confusion_counts(truth, preds)
    prec = precision(c)

    wilson = None
    if c.tp + c.fp > 0:
        wilson = wilson_interval(successes=c.tp, n=c.tp + c.fp)

    return {
        "n": c.n,
        "confusion": {"tp": c.tp, "fp": c.fp, "fn": c.fn, "tn": c.tn},
        "precision": prec,
        "recall": recall(c),
        "f1": f1(c),
        "accuracy": accuracy(c),
        "balanced_accuracy": balanced_accuracy(c),
        "mcc": mcc(c),
        "pr_auc": pr_auc(truth, scores),
        "roc_auc": roc_auc(truth, scores),
        "precision_wilson_ci": wilson,
        "scores": scores,
        "reports": reports,
        "max_period": max_period,
    }

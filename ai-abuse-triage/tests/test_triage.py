"""Tests locking the correctness/integrity properties this project depends on.

Each test's docstring states the specific property it locks and why that
property matters (a stdlib metric bug, a leaked label, a mislabeled
synthetic negative, or a scorer that fails to rank real cases above noise
would all be silent, high-consequence failures for a triage tool).
"""

from __future__ import annotations

import math

import pytest

from data.reports import all_reports, negatives, positives
from src.evaluate import evaluate
from src.metrics import (
    ConfusionCounts,
    confusion_counts,
    mcc,
    pr_auc,
    roc_auc,
)
from src.schema import AbuseReport
from src.triage import DISMISS_MAX, REVIEW_MAX, priority_score, triage

# ---------------------------------------------------------------------------
# Metrics sanity: stdlib pr_auc/roc_auc reimplementations vs hand computation
# ---------------------------------------------------------------------------


def test_pr_auc_matches_hand_computed_tiny_example():
    """A tiny 4-record fixture (2 positive, 2 negative), perfectly ranked,
    must give PR-AUC exactly 1.0: both positives score above both
    negatives, so precision is 1.0 at every recall level and the area under
    the precision-recall curve is the full unit square's worth in recall.
    """
    y_true = [True, True, False, False]
    y_score = [0.9, 0.8, 0.4, 0.1]
    result = pr_auc(y_true, y_score)
    assert result == pytest.approx(1.0)


def test_pr_auc_matches_hand_computed_imperfect_example():
    """Hand-computed fixture with one negative ranked above one positive:
    scores desc [0.9(T), 0.7(F), 0.6(T), 0.2(F)].
    Sweep: after 0.9 -> tp=1,fp=0 -> P=1.0,R=0.5
           after 0.7 -> tp=1,fp=1 -> P=0.5,R=0.5
           after 0.6 -> tp=2,fp=1 -> P=0.667,R=1.0
           after 0.2 -> tp=2,fp=2 -> P=0.5,R=1.0
    Trapezoid over (recall, precision) points (0,1),(0.5,1.0),(0.5,0.5),
    (1.0,0.667),(1.0,0.5):
      seg1: dx=0.5, avg=(1+1)/2=1.0 -> 0.5
      seg2: dx=0.0 -> 0
      seg3: dx=0.5, avg=(0.5+0.667)/2=0.5833 -> 0.29165
      seg4: dx=0.0 -> 0
      total ~= 0.79165
    """
    y_true = [True, False, True, False]
    y_score = [0.9, 0.7, 0.6, 0.2]
    result = pr_auc(y_true, y_score)
    assert result == pytest.approx(0.791666, abs=1e-4)


def test_roc_auc_matches_hand_computed_tiny_example():
    """Same perfectly-ranked fixture as the PR-AUC test: ROC-AUC must be
    exactly 1.0 when every positive outranks every negative.
    """
    y_true = [True, True, False, False]
    y_score = [0.9, 0.8, 0.4, 0.1]
    result = roc_auc(y_true, y_score)
    assert result == pytest.approx(1.0)


def test_roc_auc_matches_hand_computed_worst_case():
    """Perfectly INVERTED ranking (every negative outranks every positive)
    must give ROC-AUC exactly 0.0: TPR only starts climbing once every FP
    has already been counted, so the ROC curve hugs the bottom and right
    edges of the unit square, enclosing zero area.
    """
    y_true = [True, True, False, False]
    y_score = [0.1, 0.2, 0.8, 0.9]
    result = roc_auc(y_true, y_score)
    assert result == pytest.approx(0.0)


def test_pr_auc_and_roc_auc_none_on_single_class():
    """Single-class slices make both metrics undefined; must return None,
    not a numeric placeholder that would silently read as "bad performance"
    when the truth is "not computable" (mirrors the sibling project's
    mcc()-style refusal to silently coerce a degenerate case to a number).
    """
    all_positive_true = [True, True, True]
    all_positive_score = [0.9, 0.5, 0.1]
    assert pr_auc(all_positive_true, all_positive_score) is None
    assert roc_auc(all_positive_true, all_positive_score) is None


def test_mcc_none_guard_on_zero_marginal():
    """mcc() must return None, not 0 or a raised exception, when a marginal
    sum (e.g. every prediction is positive, so TN+FN=0) is zero.
    """
    c = ConfusionCounts(tp=5, fp=3, fn=0, tn=0)
    assert mcc(c) is None


def test_mcc_perfect_prediction_is_one():
    c = confusion_counts([True, True, False, False], [True, True, False, False])
    assert mcc(c) == pytest.approx(1.0)


# ---------------------------------------------------------------------------
# Corpus integrity
# ---------------------------------------------------------------------------


def test_positives_count_and_labels():
    """positives() must be exactly the 16 real documented cases, all
    honestly labeled synthetic=False and is_actionable=True.
    """
    pos = positives()
    assert len(pos) == 16
    assert all(not r.synthetic for r in pos)
    assert all(r.is_actionable for r in pos)


def test_negatives_count_and_labels():
    """negatives() must be at least 16 constructed reports, every one
    honestly labeled synthetic=True and is_actionable=False. This is the
    integrity requirement: a constructed negative must never be mistaken
    for a real report anywhere downstream.
    """
    neg = negatives()
    assert len(neg) >= 16
    assert all(r.synthetic for r in neg)
    assert all(not r.is_actionable for r in neg)


def test_all_reports_is_union_of_positives_and_negatives():
    assert len(all_reports()) == len(positives()) + len(negatives())


# ---------------------------------------------------------------------------
# Schema validation
# ---------------------------------------------------------------------------


def test_schema_rejects_bad_category():
    with pytest.raises(ValueError):
        AbuseReport(
            id="x", subject_id="x", alleged_category="not_a_real_category",
            integration_level="aid", evidence_source="multi_source", scale=1,
            reported_period="2025-H1", is_actionable=False, synthetic=True, raw="x",
        )


def test_schema_rejects_bad_integration():
    with pytest.raises(ValueError):
        AbuseReport(
            id="x", subject_id="x", alleged_category="spam_other",
            integration_level="not_a_real_level", evidence_source="multi_source", scale=1,
            reported_period="2025-H1", is_actionable=False, synthetic=True, raw="x",
        )


def test_schema_rejects_bad_evidence():
    with pytest.raises(ValueError):
        AbuseReport(
            id="x", subject_id="x", alleged_category="spam_other",
            integration_level="aid", evidence_source="not_a_real_source", scale=1,
            reported_period="2025-H1", is_actionable=False, synthetic=True, raw="x",
        )


# ---------------------------------------------------------------------------
# Scorer discrimination: the core finding
# ---------------------------------------------------------------------------


def test_scorer_ranks_real_cases_above_constructed_noise():
    """Core finding: the mean priority_score of the 16 real documented cases
    must be meaningfully higher than the mean of the constructed low-priority
    negatives. This is what a triage scorer is FOR: real threats above noise.
    """
    pos = positives()
    neg = negatives()
    max_period = max(r.reported_period for r in pos + neg)

    pos_mean = sum(priority_score(r, max_period=max_period) for r in pos) / len(pos)
    neg_mean = sum(priority_score(r, max_period=max_period) for r in neg) / len(neg)

    assert pos_mean > neg_mean + 20.0, (
        f"expected a clear margin, got positives_mean={pos_mean:.2f} "
        f"negatives_mean={neg_mean:.2f}"
    )


def test_integration_multiplier_increases_score():
    """An agentic case must score strictly higher than an otherwise-identical
    aid-level case, since INTEGRATION_MULTIPLIER["agentic"] >
    INTEGRATION_MULTIPLIER["aid"].
    """
    base_kwargs = dict(
        id="x", subject_id="x", alleged_category="malware_dev",
        evidence_source="multi_source", scale=5, reported_period="2025-H2",
        is_actionable=True, synthetic=False, raw="x",
    )
    aid_report = AbuseReport(integration_level="aid", **base_kwargs)
    agentic_report = AbuseReport(integration_level="agentic", **base_kwargs)

    assert priority_score(agentic_report) > priority_score(aid_report)


# ---------------------------------------------------------------------------
# triage() collapse
# ---------------------------------------------------------------------------


def test_triage_returns_only_three_actions():
    for report in all_reports():
        assert triage(report) in {"dismiss", "review", "escalate"}


def test_highest_severity_agentic_state_cyber_op_escalates():
    """The worst case the corpus can express (highest-severity category,
    agentic integration, strongest evidence, high scale, most recent period)
    must land in "escalate", proving the threshold structure is sane.
    """
    report = AbuseReport(
        id="worst", subject_id="worst-actor", alleged_category="state_cyber_ops",
        integration_level="agentic", evidence_source="multi_source", scale=50,
        reported_period="2025-H2", is_actionable=True, synthetic=False, raw="worst case",
    )
    assert triage(report, max_period="2025-H2") == "escalate"
    assert priority_score(report, max_period="2025-H2") > REVIEW_MAX


def test_lowest_severity_case_dismisses():
    report = AbuseReport(
        id="least", subject_id="noise", alleged_category="spam_other",
        integration_level="aid", evidence_source="user_report", scale=1,
        reported_period="2024-H1", is_actionable=False, synthetic=True, raw="noise",
    )
    assert triage(report, max_period="2025-H2") == "dismiss"
    assert priority_score(report, max_period="2025-H2") <= DISMISS_MAX


# ---------------------------------------------------------------------------
# evaluate() produces valid, separating metrics
# ---------------------------------------------------------------------------


def test_evaluate_mcc_and_pr_auc_in_valid_ranges():
    result = evaluate()
    assert result["mcc"] is not None
    assert -1.0 <= result["mcc"] <= 1.0
    assert result["pr_auc"] is not None
    assert 0.0 <= result["pr_auc"] <= 1.0
    assert result["roc_auc"] is not None
    assert 0.0 <= result["roc_auc"] <= 1.0


def test_evaluate_pr_auc_shows_strong_separation():
    """PR-AUC above 0.8 given the scorer's job is to rank real cases above
    constructed noise; this asserts the achieved value with headroom so a
    future regression that erodes separation (but not enough to drop below
    a much looser bound) still fails the test.
    """
    result = evaluate()
    assert result["pr_auc"] > 0.8


# ---------------------------------------------------------------------------
# Scorer never reads ground truth
# ---------------------------------------------------------------------------


def test_scorer_does_not_read_is_actionable():
    """priority_score of two reports identical in every field except
    is_actionable must be equal. If the scorer ever starts reading
    is_actionable as an input, this test catches it: label leakage into a
    triage scorer would make the evaluation numbers meaningless (the scorer
    would be "predicting" the label it was given).
    """
    shared_kwargs = dict(
        id="x", subject_id="x", alleged_category="scam_fraud",
        integration_level="runtime", evidence_source="osint", scale=3,
        reported_period="2025-H1", synthetic=False, raw="x",
    )
    actionable = AbuseReport(is_actionable=True, **shared_kwargs)
    not_actionable = AbuseReport(is_actionable=False, **shared_kwargs)

    assert priority_score(actionable) == priority_score(not_actionable)
    assert triage(actionable) == triage(not_actionable)

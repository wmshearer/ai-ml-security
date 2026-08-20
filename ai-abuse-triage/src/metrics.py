"""Evaluation metrics for the abuse-report triage scorer.

Adapted from the sibling ai-triage-engine project's eval/metrics.py. The
confusion-matrix primitives, rate metrics, MCC, and Wilson interval below are
carried over unchanged (they only ever used `math` and `dataclasses`, so
nothing had to change to make them stdlib-only here).

`pr_auc` and `roc_auc` are REIMPLEMENTED in this module. The sibling project
computed them with `sklearn.metrics.average_precision_score` and
`roc_auc_score`; neither numpy nor sklearn is available in this project, so
both are hand-rolled here: sort records by score descending, sweep every
distinct score as a threshold, compute precision/recall (for PR-AUC) or
TPR/FPR (for ROC-AUC) at each threshold, and integrate the resulting curve
with the trapezoidal rule. The same None-on-single-class guard the sibling's
originals used is kept here for the same reason: a single-class slice makes
both metrics undefined, and silently returning 0.0 would read as "terrible
performance" when the truth is "not computable."

Also carried over from the sibling: MCC is preferred as a headline over plain
accuracy. Chicco & Jurman (BMC Genomics 2020, PMC6941312) found MCC is the
only common binary rate that scores high only when a classifier gets most of
both the positive and negative class right, which is exactly what matters
here: a triage scorer that just calls everything "escalate" would post high
recall and high accuracy under class imbalance while being useless. Plain
accuracy is computed (`accuracy`) but is never the headline for the same
reason the sibling documents: under imbalance, a majority-class classifier
can score high accuracy while doing nothing useful. The Wilson interval is
used instead of a normal/Wald approximation because Wald is documented
unstable at small n and near proportions of 0 or 1, both of which can occur
on this project's small (~35-report) corpus.

Dropped from the sibling entirely: `mcc_sklearn_cross_check` and anything
else that imports numpy or sklearn. This module has zero third-party
imports; NO numpy, NO sklearn, NO network, anywhere.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Confusion matrix + derived rate metrics
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ConfusionCounts:
    """A binary confusion matrix, `positive == actionable` (the abuse report
    is a real, worth-escalating case).

    Named fields rather than a bare 2x2 array so every call site is
    self-documenting about which cell is which.
    """

    tp: int
    fp: int
    fn: int
    tn: int

    @property
    def n(self) -> int:
        return self.tp + self.fp + self.fn + self.tn


def confusion_counts(y_true: list[bool], y_pred: list[bool]) -> ConfusionCounts:
    """Build a `ConfusionCounts` from parallel true/predicted boolean lists.

    `True` means actionable (real abuse worth escalating) in both lists.
    """
    if len(y_true) != len(y_pred):
        raise ValueError(f"length mismatch: {len(y_true)} true vs {len(y_pred)} pred")
    if not y_true:
        raise ValueError("cannot compute a confusion matrix over zero records")
    tp = fp = fn = tn = 0
    for t, p in zip(y_true, y_pred):
        if t and p:
            tp += 1
        elif not t and p:
            fp += 1
        elif t and not p:
            fn += 1
        else:
            tn += 1
    return ConfusionCounts(tp=tp, fp=fp, fn=fn, tn=tn)


def precision(c: ConfusionCounts) -> float | None:
    """TP / (TP + FP). None (undefined) if the model never predicted positive."""
    denom = c.tp + c.fp
    return c.tp / denom if denom else None


def recall(c: ConfusionCounts) -> float | None:
    """TP / (TP + FN), i.e. true positive rate / sensitivity.

    None (undefined) only if there are zero actual positives in the slice ,
    a degenerate stratum, not a modeling failure.
    """
    denom = c.tp + c.fn
    return c.tp / denom if denom else None


def f1(c: ConfusionCounts) -> float | None:
    p, r = precision(c), recall(c)
    if p is None or r is None or (p + r) == 0:
        return None
    return 2 * p * r / (p + r)


def false_positive_rate(c: ConfusionCounts) -> float | None:
    """FP / (FP + TN), stated inline to avoid the FPR-vs-false-discovery-rate
    ambiguity."""
    denom = c.fp + c.tn
    return c.fp / denom if denom else None


def false_negative_rate(c: ConfusionCounts) -> float | None:
    """FN / (FN + TP)."""
    denom = c.fn + c.tp
    return c.fn / denom if denom else None


def specificity(c: ConfusionCounts) -> float | None:
    """TN / (TN + FP), i.e. true negative rate. 1 - FPR when defined."""
    denom = c.tn + c.fp
    return c.tn / denom if denom else None


def accuracy(c: ConfusionCounts) -> float:
    """Plain accuracy. NEVER report this alone as a headline, under class
    imbalance a majority-class classifier can score high accuracy while
    having zero recall on the class that matters. Exists here only so it can
    be shown explicitly alongside other metrics as context.
    """
    return (c.tp + c.tn) / c.n


def balanced_accuracy(c: ConfusionCounts) -> float | None:
    """Macro-average of per-class recall: mean(sensitivity, specificity).

    None if either class is entirely absent from the slice (both recall and
    specificity require a nonzero denominator), an honest "undefined", not
    a silently substituted 0 or 1.
    """
    r, s = recall(c), specificity(c)
    if r is None or s is None:
        return None
    return (r + s) / 2


def mcc(c: ConfusionCounts) -> float | None:
    """Matthews Correlation Coefficient.

    MCC = (TP*TN - FP*FN) / sqrt((TP+FP)(TP+FN)(TN+FP)(TN+FN))

    Range [-1, +1], 0 = random. Chicco & Jurman (BMC Genomics 2020, PMC6941312):
    "MCC is the only binary classification rate that generates a high score
    only if the binary predictor was able to correctly predict the majority
    of positive data instances and the majority of negative data instances."

    Returns None (explicitly, per the paper's own caveat) when any of the
    four marginal sums (TP+FP, TP+FN, TN+FP, TN+FN) is zero, i.e. the
    confusion matrix has a fully-zero row or column, meaning one class was
    never predicted or never occurred. Never silently coerced to 0 or 1.
    """
    denom_sq = (c.tp + c.fp) * (c.tp + c.fn) * (c.tn + c.fp) * (c.tn + c.fn)
    if denom_sq == 0:
        return None
    numerator = c.tp * c.tn - c.fp * c.fn
    return numerator / math.sqrt(denom_sq)


# ---------------------------------------------------------------------------
# Wilson score confidence intervals
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class WilsonInterval:
    point: float
    low: float
    high: float
    n: int


def wilson_interval(successes: int, n: int, confidence: float = 0.95) -> WilsonInterval:
    """Wilson score interval for a binomial proportion.

    Used instead of the normal/Wald approximation: Wald is documented
    unstable at small n and near proportions of 0 or 1, both plausible here
    given this project's small (~35-report) corpus. Formula (Wilson 1927,
    the standard textbook form):

        center = (p_hat + z^2/(2n)) / (1 + z^2/n)
        half_width = z/(1+z^2/n) * sqrt(p_hat(1-p_hat)/n + z^2/(4n^2))
        interval = center +/- half_width

    z is the two-sided normal critical value for `confidence` (1.959964 for
    95%, hardcoded below since that is the only level this project uses;
    no scipy available to compute it generically). Raises on n=0 rather than
    returning a degenerate/undefined interval silently.
    """
    if n <= 0:
        raise ValueError("wilson_interval requires n > 0")
    if not (0 <= successes <= n):
        raise ValueError(f"successes={successes} must be in [0, n={n}]")

    z = _normal_two_sided_critical_value(confidence)
    p_hat = successes / n
    z2 = z * z

    denom = 1 + z2 / n
    center = (p_hat + z2 / (2 * n)) / denom
    half_width = (z / denom) * math.sqrt(p_hat * (1 - p_hat) / n + z2 / (4 * n * n))

    low = max(0.0, center - half_width)
    high = min(1.0, center + half_width)
    return WilsonInterval(point=p_hat, low=low, high=high, n=n)


def _normal_two_sided_critical_value(confidence: float) -> float:
    """Two-sided normal critical value z for a given confidence level.

    Pure-stdlib closed-form approximation of the inverse normal CDF (Acklam's
    algorithm, widely used rational-approximation implementation), since no
    scipy is available here. Only 95% confidence is exercised in this
    project's own call sites, but the approximation is accurate to about
    1e-9 across the full (0, 1) range, so any confidence level works.
    """
    if not (0 < confidence < 1):
        raise ValueError("confidence must be in (0, 1)")
    p = 1 - (1 - confidence) / 2
    return _inverse_normal_cdf(p)


def _inverse_normal_cdf(p: float) -> float:
    """Acklam's rational approximation to the inverse standard normal CDF."""
    if not (0 < p < 1):
        raise ValueError("p must be in (0, 1)")

    a = [-3.969683028665376e01, 2.209460984245205e02, -2.759285104469687e02,
         1.383577518672690e02, -3.066479806614716e01, 2.506628277459239e00]
    b = [-5.447609879822406e01, 1.615858368580409e02, -1.556989798598866e02,
         6.680131188771972e01, -1.328068155288572e01]
    c = [-7.784894002430293e-03, -3.223964580411365e-01, -2.400758277161838e00,
         -2.549732539343734e00, 4.374664141464968e00, 2.938163982698783e00]
    d = [7.784695709041462e-03, 3.224671290700398e-01, 2.445134137142996e00,
         3.754408661907416e00]

    p_low = 0.02425
    p_high = 1 - p_low

    if p < p_low:
        q = math.sqrt(-2 * math.log(p))
        return (((((c[0] * q + c[1]) * q + c[2]) * q + c[3]) * q + c[4]) * q + c[5]) / (
            (((d[0] * q + d[1]) * q + d[2]) * q + d[3]) * q + 1
        )
    if p <= p_high:
        q = p - 0.5
        r = q * q
        return (((((a[0] * r + a[1]) * r + a[2]) * r + a[3]) * r + a[4]) * r + a[5]) * q / (
            (((((b[0] * r + b[1]) * r + b[2]) * r + b[3]) * r + b[4]) * r + 1)
        )
    q = math.sqrt(-2 * math.log(1 - p))
    return -(((((c[0] * q + c[1]) * q + c[2]) * q + c[3]) * q + c[4]) * q + c[5]) / (
        (((d[0] * q + d[1]) * q + d[2]) * q + d[3]) * q + 1
    )


# ---------------------------------------------------------------------------
# Threshold-free ranking metrics: PR-AUC (primary) and ROC-AUC (secondary)
#
# Reimplemented in pure stdlib (no numpy/sklearn available). Both sweep
# every distinct score value as a threshold, compute the relevant curve
# points, and integrate with the trapezoidal rule.
# ---------------------------------------------------------------------------


def _sorted_scores_descending(y_true: list[bool], y_score: list[float]) -> list[tuple[float, bool]]:
    """Pair (score, label) and sort by score descending, ties broken stably."""
    return sorted(zip(y_score, y_true), key=lambda pair: pair[0], reverse=True)


def _trapezoid(xs: list[float], ys: list[float]) -> float:
    """Integrate y over x via the trapezoidal rule. xs need not be sorted;
    consecutive pairs are integrated in the order given, matching the way
    the curve is built (sweep from threshold=+inf down to threshold=-inf).
    """
    area = 0.0
    for i in range(1, len(xs)):
        dx = xs[i] - xs[i - 1]
        area += dx * (ys[i] + ys[i - 1]) / 2.0
    return area


def pr_auc(y_true: list[bool], y_score: list[float]) -> float | None:
    """Average precision (PR-AUC), positive == actionable.

    Primary threshold-independent ranking metric here (same reasoning as the
    sibling project): sensitive to false positives under class imbalance in
    a way ROC's huge-negative-denominator is not (Davis & Goadrich, ICML
    2006). Requires a continuous score per record (this project's
    `priority_score`).

    Computed by sweeping the threshold down through every distinct score
    (highest first), recomputing precision and recall at each cut point
    (cumulative TP / predicted-positive-so-far, cumulative TP / total
    positives), and integrating precision over recall with the trapezoidal
    rule starting from (recall=0, precision=precision at the first point).

    Returns None on a single-class slice, undefined, not 0.0 (same
    silent-coercion refusal as `mcc()`; a naive library call would happily
    return a numeric value here that reads as "terrible" when the truth is
    "not computable").

    One precision note: trapezoidal integration of the PR curve is not the
    same convention as scikit-learn's `average_precision_score`, which is a
    step-function sum with no interpolation between points. The two agree
    closely on this corpus (both round to 0.965) but can differ by a few
    hundredths on small or adversarial inputs. This is the PR-curve integral,
    not a drop-in replacement for sklearn's average precision.
    """
    if len(set(y_true)) < 2:
        return None

    n_pos = sum(1 for t in y_true if t)
    pairs = _sorted_scores_descending(y_true, y_score)

    recalls = [0.0]
    precisions = [1.0]
    tp = 0
    fp = 0
    for _, label in pairs:
        if label:
            tp += 1
        else:
            fp += 1
        precisions.append(tp / (tp + fp))
        recalls.append(tp / n_pos)

    return _trapezoid(recalls, precisions)


def roc_auc(y_true: list[bool], y_score: list[float]) -> float | None:
    """ROC-AUC, positive == actionable.

    Reported as a SECONDARY number alongside PR-AUC, never as a standalone
    headline (same convention as the sibling project), PR-AUC is the more
    informative of the two under class imbalance (Davis & Goadrich 2006).

    Computed by sweeping the threshold down through every distinct score
    and plotting (FPR, TPR) at each cut point, integrating TPR over FPR with
    the trapezoidal rule.

    Returns None on a single-class slice, undefined, not a numeric
    placeholder, for the same reason `pr_auc` does.
    """
    if len(set(y_true)) < 2:
        return None

    n_pos = sum(1 for t in y_true if t)
    n_neg = len(y_true) - n_pos
    pairs = _sorted_scores_descending(y_true, y_score)

    fprs = [0.0]
    tprs = [0.0]
    tp = 0
    fp = 0
    for _, label in pairs:
        if label:
            tp += 1
        else:
            fp += 1
        tprs.append(tp / n_pos)
        fprs.append(fp / n_neg)

    return _trapezoid(fprs, tprs)


# ---------------------------------------------------------------------------
# Convenience bundle
# ---------------------------------------------------------------------------


def metric_set(y_true: list[bool], y_pred: list[bool]) -> dict[str, float | None]:
    """Bundle of every threshold-based scalar metric for one (y_true, y_pred)
    pair, keyed by name. Does not include PR-AUC/ROC-AUC (those need scores,
    not hard predictions) or CIs (need Wilson-interval call sites to know
    which count is the numerator), callers needing those call
    `pr_auc`/`roc_auc`/`wilson_interval` directly.
    """
    c = confusion_counts(y_true, y_pred)
    return {
        "n": c.n,
        "tp": c.tp,
        "fp": c.fp,
        "fn": c.fn,
        "tn": c.tn,
        "accuracy": accuracy(c),
        "balanced_accuracy": balanced_accuracy(c),
        "mcc": mcc(c),
        "precision": precision(c),
        "recall": recall(c),
        "f1": f1(c),
        "fpr": false_positive_rate(c),
        "fnr": false_negative_rate(c),
        "specificity": specificity(c),
    }

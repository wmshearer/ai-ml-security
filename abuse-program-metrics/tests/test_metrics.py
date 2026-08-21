import math
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.metrics import (
    DIVERGENCE_THRESHOLD,
    SMALL_SAMPLE_THRESHOLD,
    Stratum,
    duration_stats,
    matthews_corrcoef,
    percentile,
    strata_report,
)


# ---------------------------------------------------------------------------
# percentile()
# ---------------------------------------------------------------------------

def test_percentile_single_value():
    assert percentile([42], 90) == 42


def test_percentile_p50_matches_median_on_odd_length():
    values = sorted([1, 3, 5, 7, 9])
    assert percentile(values, 50) == 5


def test_percentile_p100_is_max():
    values = sorted([4, 8, 15, 16, 23, 42])
    assert percentile(values, 100) == 42


def test_percentile_p0_is_min():
    values = sorted([4, 8, 15, 16, 23, 42])
    assert percentile(values, 0) == 4


# ---------------------------------------------------------------------------
# duration_stats()
# ---------------------------------------------------------------------------

def test_duration_stats_basic_counts():
    durations = [10, 20, 30, 40, 50]
    stats = duration_stats(durations)
    assert stats.count == 5
    assert stats.mean == 30
    assert stats.median == 30


def test_duration_stats_flags_small_sample():
    durations = list(range(1, 15))  # 14 values, below threshold of 30
    stats = duration_stats(durations)
    assert stats.count < SMALL_SAMPLE_THRESHOLD
    assert stats.small_sample_warning is True
    assert "WARNING" in stats.report()
    assert "Davidovic" in stats.report()


def test_duration_stats_no_warning_above_threshold():
    durations = list(range(1, SMALL_SAMPLE_THRESHOLD + 20))
    stats = duration_stats(durations)
    assert stats.count >= SMALL_SAMPLE_THRESHOLD
    assert stats.small_sample_warning is False
    assert "WARNING" not in stats.report()


def test_duration_stats_empty_raises():
    try:
        duration_stats([])
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_duration_stats_skewed_mean_vs_median():
    # One long outlier incident should pull the mean well above the median,
    # which is exactly the distortion the percentile/count report guards
    # against.
    durations = [5, 6, 7, 8, 9, 500]
    stats = duration_stats(durations)
    assert stats.mean > stats.median * 5


# ---------------------------------------------------------------------------
# matthews_corrcoef()
# ---------------------------------------------------------------------------

def test_mcc_perfect_classifier():
    assert matthews_corrcoef(tp=50, fp=0, tn=50, fn=0) == 1.0


def test_mcc_perfectly_wrong_classifier():
    assert matthews_corrcoef(tp=0, fp=50, tn=0, fn=50) == -1.0


def test_mcc_chance_classifier_is_zero():
    # Independent of label: precision/recall matches base rate exactly.
    assert matthews_corrcoef(tp=25, fp=25, tn=25, fn=25) == 0.0


def test_mcc_undefined_when_a_marginal_sum_is_zero():
    # No predicted negatives at all (tn=fn=0): denominator is zero.
    result = matthews_corrcoef(tp=10, fp=5, tn=0, fn=0)
    assert math.isnan(result)


def test_mcc_matches_ai_triage_engine_eventid1():
    # Reconstructed cells for the real EventID 1 (process creation) stratum:
    # MCC 0.695, precision 87.5%, recall 61.8%, per ai-triage-engine.
    mcc = matthews_corrcoef(tp=21, fp=3, tn=170, fn=13)
    assert round(mcc, 3) == 0.695
    precision = 21 / (21 + 3)
    recall = 21 / (21 + 13)
    assert round(precision, 3) == 0.875
    assert round(recall, 3) == 0.618


def test_mcc_matches_ai_triage_engine_eventid13():
    # Reconstructed cells for the real EventID 13 (registry value set)
    # stratum: MCC -0.693, actively worse than guessing, per ai-triage-engine.
    mcc = matthews_corrcoef(tp=0, fp=63, tn=15, fn=22)
    assert round(mcc, 3) == -0.693


# ---------------------------------------------------------------------------
# strata_report() / pooled-vs-strata divergence flag
# ---------------------------------------------------------------------------

def test_divergence_flag_fires_on_real_triage_numbers():
    strata = [
        Stratum(label="EventID 1", tp=21, fp=3, tn=170, fn=13),
        Stratum(label="EventID 13", tp=0, fp=63, tn=15, fn=22),
    ]
    result = strata_report(strata)
    assert round(result.pooled_mcc, 3) == 0.096
    assert result.diverges is True
    assert "EventID 13" in result.divergence_detail


def test_divergence_flag_does_not_fire_on_uniform_strata():
    # Same tp/fp/tn/fn ratios in every stratum: pooling should not distort
    # anything, so the flag must stay off.
    strata = [
        Stratum(label="stratum A", tp=40, fp=10, tn=40, fn=10),
        Stratum(label="stratum B", tp=40, fp=10, tn=40, fn=10),
        Stratum(label="stratum C", tp=40, fp=10, tn=40, fn=10),
    ]
    result = strata_report(strata)
    for label, mcc in result.per_stratum_mcc.items():
        assert abs(mcc - result.pooled_mcc) <= DIVERGENCE_THRESHOLD
    assert result.diverges is False


def test_strata_report_empty_raises():
    try:
        strata_report([])
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_stratum_precision_undefined_when_nothing_flagged():
    # tp+fp == 0: the stratum never flagged anything, so precision has no
    # denominator.
    s = Stratum(label="no predicted positives", tp=0, fp=0, tn=10, fn=5)
    assert s.precision() is None
    assert s.recall() == 0.0


def test_stratum_recall_undefined_when_no_real_positives():
    # tp+fn == 0: the stratum has no actual positive cases at all.
    s = Stratum(label="no real positives", tp=0, fp=3, tn=10, fn=0)
    assert s.recall() is None
    assert s.precision() == 0.0

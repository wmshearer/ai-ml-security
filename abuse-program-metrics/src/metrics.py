"""Metrics for a leadership-facing security/abuse program report.

Two calculations, both standard library only:

1. Incident duration stats (mean, median, p50/p90/p95, count) with a warning
   when the sample is too small for the mean to mean anything. Per Stepan
   Davidovic (Google), "Incident Metrics in SRE": a Monte Carlo simulation of
   incident populations shows that at realistic monthly incident volumes,
   month-to-month movement in the MEAN is dominated by statistical noise, not
   real signal, which makes it "poorly suited for decision making or trend
   analysis." Percentiles and counts hold up better at the same volumes. This
   module never reports a mean without also printing that warning.

2. Per-stratum vs pooled classifier quality (MCC, precision, recall), with a
   flag when the pooled figure and the strata disagree materially. This is
   the ai-triage-engine and sockpuppet-stylometry failure made mechanical: a
   single pooled number can average a working detector and a harmful one
   into something that looks like uniform mediocrity.

No third-party dependencies. MCC is implemented from its closed-form formula.
"""

from __future__ import annotations

import math
import statistics
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Section 1: incident duration stats
# ---------------------------------------------------------------------------

# Below this many incidents, the mean is flagged as unstable. This is not a
# statistically derived cutoff, it is a practical trip-wire: Davidovic's
# simulation shows the noise problem is worst at the incident volumes a
# normal team actually sees (tens per month, not thousands), so any small
# monthly sample should carry the warning by default.
SMALL_SAMPLE_THRESHOLD = 30


def percentile(sorted_values: list[float], pct: float) -> float:
    """Nearest-rank percentile on an already-sorted list. pct is 0-100."""
    if not sorted_values:
        raise ValueError("no values to compute a percentile from")
    if len(sorted_values) == 1:
        return sorted_values[0]
    rank = (pct / 100) * (len(sorted_values) - 1)
    lo = int(rank)
    hi = min(lo + 1, len(sorted_values) - 1)
    frac = rank - lo
    return sorted_values[lo] + (sorted_values[hi] - sorted_values[lo]) * frac


@dataclass
class DurationStats:
    count: int
    mean: float
    median: float
    p50: float
    p90: float
    p95: float
    small_sample_warning: bool

    def report(self, unit: str = "minutes") -> str:
        lines = [
            f"n = {self.count}",
            f"mean   = {self.mean:.1f} {unit}",
            f"median = {self.median:.1f} {unit}  (p50)",
            f"p90    = {self.p90:.1f} {unit}",
            f"p95    = {self.p95:.1f} {unit}",
        ]
        if self.small_sample_warning:
            lines.append(
                f"WARNING: n={self.count} is below the small-sample threshold "
                f"({SMALL_SAMPLE_THRESHOLD}). Per Davidovic (Google), 'Incident "
                "Metrics in SRE,' the mean is poorly suited for decision making "
                "or trend analysis at realistic incident volumes. Read the "
                "percentiles and the count. Do not act on the mean alone."
            )
        return "\n".join(lines)


def duration_stats(durations: list[float]) -> DurationStats:
    """Given a list of incident durations (any consistent unit), return
    mean, median, p50/p90/p95, and count, flagging small-sample instability.
    """
    if not durations:
        raise ValueError("no durations given")
    ordered = sorted(durations)
    return DurationStats(
        count=len(ordered),
        mean=statistics.mean(ordered),
        median=statistics.median(ordered),
        p50=percentile(ordered, 50),
        p90=percentile(ordered, 90),
        p95=percentile(ordered, 95),
        small_sample_warning=len(ordered) < SMALL_SAMPLE_THRESHOLD,
    )


# ---------------------------------------------------------------------------
# Section 2: per-stratum vs pooled classifier quality
# ---------------------------------------------------------------------------

# How far a pooled MCC can drift from the strata before we call it a material
# divergence. 0.3 is set as a loose bar on purpose: the ai-triage-engine case
# (pooled 0.014, strata at 0.695 and -0.693) clears it by a wide margin, and
# the point of this constant is to catch cases like that, not to nitpick
# small run-to-run wobble.
DIVERGENCE_THRESHOLD = 0.3


@dataclass
class Stratum:
    label: str
    tp: int
    fp: int
    tn: int
    fn: int

    @property
    def n(self) -> int:
        return self.tp + self.fp + self.tn + self.fn

    def mcc(self) -> float:
        return matthews_corrcoef(self.tp, self.fp, self.tn, self.fn)

    def precision(self) -> float | None:
        denom = self.tp + self.fp
        return self.tp / denom if denom else None

    def recall(self) -> float | None:
        denom = self.tp + self.fn
        return self.tp / denom if denom else None


def matthews_corrcoef(tp: int, fp: int, tn: int, fn: int) -> float:
    """Matthews Correlation Coefficient from a 2x2 confusion matrix.

    MCC = (TP*TN - FP*FN) / sqrt((TP+FP)(TP+FN)(TN+FP)(TN+FN))

    Ranges -1 (perfectly wrong) to +1 (perfect), 0 is chance. Unlike accuracy
    it does not reward a classifier for ignoring the minority class, which is
    why it is the headline metric in ai-triage-engine and this module.
    """
    numerator = (tp * tn) - (fp * fn)
    denom_sq = (tp + fp) * (tp + fn) * (tn + fp) * (tn + fn)
    if denom_sq == 0:
        # One of the four marginal sums is zero (e.g. no positive class in
        # this stratum at all). MCC is undefined here, not zero.
        return float("nan")
    return numerator / (denom_sq ** 0.5)


@dataclass
class StrataReport:
    strata: list[Stratum]
    pooled: Stratum
    pooled_mcc: float
    per_stratum_mcc: dict[str, float] = field(default_factory=dict)
    diverges: bool = False
    divergence_detail: str = ""

    def report(self) -> str:
        lines = [f"pooled MCC = {self.pooled_mcc:.3f}  (n={self.pooled.n})", ""]
        for s in self.strata:
            m = self.per_stratum_mcc[s.label]
            m_str = "n/a" if math.isnan(m) else f"{m:.3f}"
            p = s.precision()
            r = s.recall()
            p_str = "n/a" if p is None else f"{p:.1%}"
            r_str = "n/a" if r is None else f"{r:.1%}"
            lines.append(
                f"  {s.label:<20} MCC={m_str:<8} precision={p_str:<8} "
                f"recall={r_str:<8} n={s.n}"
            )
        lines.append("")
        if self.diverges:
            lines.append(f"FLAG: {self.divergence_detail}")
        else:
            lines.append(
                "No material divergence: pooled MCC is within "
                f"{DIVERGENCE_THRESHOLD:.1f} of every stratum."
            )
        return "\n".join(lines)


def strata_report(strata: list[Stratum]) -> StrataReport:
    """Compute per-stratum and pooled MCC, and flag when the pooled figure
    differs materially from one or more strata (the ai-triage-engine /
    sockpuppet-stylometry failure, made mechanical).
    """
    if not strata:
        raise ValueError("no strata given")

    pooled = Stratum(
        label="pooled",
        tp=sum(s.tp for s in strata),
        fp=sum(s.fp for s in strata),
        tn=sum(s.tn for s in strata),
        fn=sum(s.fn for s in strata),
    )
    pooled_mcc = pooled.mcc()

    per_stratum_mcc = {}
    worst_gap = 0.0
    worst_label = None
    for s in strata:
        m = s.mcc()
        per_stratum_mcc[s.label] = m
        if not math.isnan(m) and not math.isnan(pooled_mcc):
            gap = abs(m - pooled_mcc)
            if gap > worst_gap:
                worst_gap = gap
                worst_label = s.label

    diverges = worst_gap > DIVERGENCE_THRESHOLD
    detail = ""
    if diverges:
        detail = (
            f"stratum '{worst_label}' MCC ({per_stratum_mcc[worst_label]:.3f}) "
            f"differs from pooled MCC ({pooled_mcc:.3f}) by {worst_gap:.3f}, "
            f"more than the {DIVERGENCE_THRESHOLD:.1f} threshold. The pooled "
            "figure is not a safe summary of this data. Report per-stratum."
        )

    return StrataReport(
        strata=strata,
        pooled=pooled,
        pooled_mcc=pooled_mcc,
        per_stratum_mcc=per_stratum_mcc,
        diverges=diverges,
        divergence_detail=detail,
    )


# ---------------------------------------------------------------------------
# Demo data and CLI
# ---------------------------------------------------------------------------

def _demo_durations() -> list[float]:
    """Illustrative sample data: time-to-detect in minutes for a small
    monthly incident count. Not from any sibling project; labelled here as
    what it is, a small, noisy sample built on purpose to demonstrate the
    small-sample warning.
    """
    return [4, 6, 7, 9, 11, 12, 14, 18, 22, 26, 31, 44, 58, 210]


def _demo_strata() -> list[Stratum]:
    """Reconstructed from ai-triage-engine (LLM alert triage over 1,925
    Windows security events, malicious vs benign). ai-triage-engine reports
    MCC, precision, and recall per event type, not raw confusion-matrix
    cells, so the tp/fp/tn/fn counts below are back-solved to match its
    published figures: EventID 1 at MCC 0.695 with 87.5% precision and 61.8%
    recall, EventID 13 at MCC -0.693. See docs/METRICS.md for the source
    figures and this reconstruction's cell counts.
    """
    return [
        # EventID 1, process creation: the strong stratum.
        Stratum(label="EventID 1 (process creation)", tp=21, fp=3, tn=170, fn=13),
        # EventID 13, registry value set: the harmful stratum.
        Stratum(label="EventID 13 (registry value set)", tp=0, fp=63, tn=15, fn=22),
    ]


def main() -> None:
    print("=== Incident duration stats (illustrative sample data) ===\n")
    stats = duration_stats(_demo_durations())
    print(stats.report())

    print("\n=== Per-stratum vs pooled classifier quality ===")
    print("(MCC, precision and recall are ai-triage-engine's published figures.")
    print(" The confusion-matrix cells behind them are back-solved to reproduce")
    print(" those figures, since that project reports scores rather than counts.")
    print(" So the pooled MCC here is this reconstruction's, not its published")
    print(" 0.014. See docs/METRICS.md.)\n")
    strata_result = strata_report(_demo_strata())
    print(strata_result.report())


if __name__ == "__main__":
    main()

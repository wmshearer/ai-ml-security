"""Deterministic, rule-based priority scorer for AI-abuse reports.

Structured like a CVSS base score: a handful of named, documented weight
tables combine into one composite 0-100 number, with every weight visible
and inspectable at the top of this module rather than buried in the scoring
function. Nothing here is learned or tuned against ground truth; it is a
fixed set of judgment calls about what makes an AI-abuse report more or less
urgent, encoded as constants.

IMPORTANT: the scorer never reads `AbuseReport.is_actionable`. That field is
ground truth, used only by `src/evaluate.py` to measure the scorer after the
fact. Mirrors the sibling ai-triage-engine project's "labels are never
inputs" discipline: `priority_score` and `triage` below take an `AbuseReport`
and touch only its non-label fields (`alleged_category`, `integration_level`,
`evidence_source`, `scale`, `reported_period`). If a future edit adds a
`report.is_actionable` read to either function, that is a leakage bug.
"""

from __future__ import annotations

from src.schema import AbuseReport

# ---------------------------------------------------------------------------
# Weight tables
# ---------------------------------------------------------------------------

# 1. SEVERITY: base weight per alleged category, 0-100 scale.
# state_cyber_ops and csam_adjacent are both treated as highest-severity
# but for different reasons (state_cyber_ops: national-security-grade
# capability misuse; csam_adjacent: severity that is orthogonal to
# state/criminal actor sophistication, it is highest regardless of who is
# doing it). malware_dev and influence_op sit in the upper-middle band,
# scam_fraud below that, spam_other lowest.
SEVERITY_WEIGHT: dict[str, float] = {
    "csam_adjacent": 100.0,
    "state_cyber_ops": 95.0,
    "malware_dev": 75.0,
    "influence_op": 60.0,
    "scam_fraud": 45.0,
    "spam_other": 10.0,
}

# 2. INTEGRATION: AI-specific severity multiplier, from the aiti case data's
# own integration axis (aid < runtime < agentic). An agentic operation where
# the model drives the operation itself is categorically more dangerous than
# the same category of abuse where a human merely used the model as a
# drafting aid, so this multiplies rather than adds to severity: an agentic
# cyber-op should outrank an aid-level phishing case even within the same
# alleged_category ranking.
INTEGRATION_MULTIPLIER: dict[str, float] = {
    "aid": 1.0,
    "runtime": 1.3,
    "agentic": 1.7,
}

# 3. EVIDENCE: confidence/evidence-strength weight. Reports corroborated by
# multiple independent sources are far more actionable than a single
# unverified user complaint; automated_signal and osint sit in between.
EVIDENCE_WEIGHT: dict[str, float] = {
    "multi_source": 1.0,
    "automated_signal": 0.8,
    "osint": 0.65,
    "user_report": 0.4,
}

# 4. SCALE: reach of the abuse, log-scaled so a jump from 1 to 10 targets
# matters more than a jump from 1000 to 1009. scale=0 maps to log(1)=0 via
# the +1 offset (avoids log(0)). Divisor chosen so a scale of ~100 targets
# saturates the bonus at 1.0; larger campaigns still gain a little beyond
# that via the log curve but with rapidly diminishing returns.
SCALE_LOG_DIVISOR = 4.6  # ln(100) ~= 4.605, so scale=100 -> ~1.0 before cap
SCALE_BONUS_CAP = 1.3  # max multiplicative bonus at very large scale


def _scale_factor(scale: int) -> float:
    import math

    raw = math.log(scale + 1) / SCALE_LOG_DIVISOR
    return 1.0 + min(raw, SCALE_BONUS_CAP)


# 5. RECENCY: newer reports score higher. Reports are bucketed into
# half-year periods ("2024-H1", "2025-H1", "2025-H2", ...); recency decays
# linearly per half-year step back from the newest period present in the
# scored set, floored so old reports are downweighted but never zeroed out
# (an old report can still matter, just less urgently than a fresh one).
RECENCY_DECAY_PER_PERIOD = 0.12  # fraction lost per half-year step back
RECENCY_FLOOR = 0.5  # never decay below this multiplier


def _period_index(period: str) -> int:
    """Map a "YYYY-H1"/"YYYY-H2" period string to a sortable integer (half-years
    since year 0), so periods can be subtracted to get a step count.
    """
    year_str, half_str = period.split("-H")
    return int(year_str) * 2 + (int(half_str) - 1)


def _recency_factor(period: str, max_period: str) -> float:
    steps_back = _period_index(max_period) - _period_index(period)
    steps_back = max(steps_back, 0)
    factor = 1.0 - RECENCY_DECAY_PER_PERIOD * steps_back
    return max(factor, RECENCY_FLOOR)


# ---------------------------------------------------------------------------
# Composite score
# ---------------------------------------------------------------------------

# Scaling applied to the raw (severity * integration * evidence * scale *
# recency) product to land the composite in a 0-100 range for the weight
# combinations actually seen in this corpus, then hard-clamped to [0, 100]
# as a safety net for any input outside that expected range.
COMPOSITE_SCALE = 0.62


def priority_score(report: AbuseReport, max_period: str | None = None) -> float:
    """Composite 0-100 triage priority score.

    Formula (CVSS-base-score-style weighted/multiplicative composite):

        raw = SEVERITY_WEIGHT[category]
            * INTEGRATION_MULTIPLIER[integration_level]
            * EVIDENCE_WEIGHT[evidence_source]
            * scale_factor(scale)
            * recency_factor(reported_period, max_period)

        priority_score = clamp(raw * COMPOSITE_SCALE, 0, 100)

    `max_period` is the newest reported_period across the set being scored
    (the recency anchor); if not given, the report's own period is used as
    the anchor, which makes its own recency_factor 1.0 (report is "as recent
    as the newest report" when scored alone).

    Does not read `report.is_actionable`, see module docstring.
    """
    anchor = max_period if max_period is not None else report.reported_period

    severity = SEVERITY_WEIGHT[report.alleged_category]
    integration = INTEGRATION_MULTIPLIER[report.integration_level]
    evidence = EVIDENCE_WEIGHT[report.evidence_source]
    scale = _scale_factor(report.scale)
    recency = _recency_factor(report.reported_period, anchor)

    raw = severity * integration * evidence * scale * recency
    score = raw * COMPOSITE_SCALE
    return max(0.0, min(100.0, score))


# ---------------------------------------------------------------------------
# 3-way triage action
# ---------------------------------------------------------------------------

# Thresholds mirroring the sibling project's benign/suspicious/malicious
# 3-way collapse pattern, applied here to the composite priority score.
DISMISS_MAX = 30.0    # score <= this -> dismiss
REVIEW_MAX = 65.0      # DISMISS_MAX < score <= this -> review; above -> escalate


def triage(report: AbuseReport, max_period: str | None = None) -> str:
    """Collapse `priority_score` into a 3-way action: dismiss, review, or
    escalate, via the named thresholds above.

    Does not read `report.is_actionable`, see module docstring.
    """
    score = priority_score(report, max_period=max_period)
    if score <= DISMISS_MAX:
        return "dismiss"
    if score <= REVIEW_MAX:
        return "review"
    return "escalate"

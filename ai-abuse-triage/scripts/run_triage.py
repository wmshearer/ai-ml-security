#!/usr/bin/env python3
"""Runnable CLI: score every AI-abuse report in the corpus, print the
priority-ranked table, and print the evaluation metrics.

Usage: python3 scripts/run_triage.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from data.reports import all_reports, negatives, positives
from src.evaluate import evaluate
from src.triage import priority_score, triage


def _fmt(value, digits=3):
    if value is None:
        return "n/a"
    return f"{value:.{digits}f}"


def main() -> None:
    print("=" * 78)
    print("AI-ABUSE REPORT TRIAGE SCORER")
    print("Deterministic, rule-based priority scoring. No live LLM, no network.")
    print("=" * 78)

    pos = positives()
    neg = negatives()
    reports = all_reports()
    print()
    print(f"Corpus: {len(reports)} reports total")
    print(f"  {len(pos)} real documented cases (synthetic=False, from ai-threat-intel-analysis)")
    print(f"  {len(neg)} constructed low-priority reports (synthetic=True, NOT real incidents)")
    print(f"  class balance: {len(pos)} actionable / {len(neg)} not actionable")

    max_period = max(r.reported_period for r in reports)
    ranked = sorted(
        reports,
        key=lambda r: priority_score(r, max_period=max_period),
        reverse=True,
    )

    print()
    print("-" * 78)
    print("TOP 10 BY PRIORITY SCORE")
    print("-" * 78)
    header = f"{'subject_id':<32}{'category':<16}{'integ.':<9}{'evidence':<17}{'score':>7}  action"
    print(header)
    for report in ranked[:10]:
        score = priority_score(report, max_period=max_period)
        action = triage(report, max_period=max_period)
        tag = "" if not report.synthetic else "  [synthetic]"
        print(
            f"{report.subject_id:<32}{report.alleged_category:<16}"
            f"{report.integration_level:<9}{report.evidence_source:<17}"
            f"{score:>7.2f}  {action}{tag}"
        )

    result = evaluate()
    print()
    print("-" * 78)
    print("EVALUATION METRICS")
    print("(measures whether the scorer ranks the 16 real cases above the")
    print(" constructed noise; is_actionable ground truth vs triage() != dismiss)")
    print("-" * 78)
    c = result["confusion"]
    print(f"n = {result['n']}")
    print(f"confusion: tp={c['tp']} fp={c['fp']} fn={c['fn']} tn={c['tn']}")
    print(f"precision            {_fmt(result['precision'])}")
    print(f"recall               {_fmt(result['recall'])}")
    print(f"f1                   {_fmt(result['f1'])}")
    print(f"accuracy             {_fmt(result['accuracy'])}  (context only, never the headline)")
    print(f"balanced_accuracy    {_fmt(result['balanced_accuracy'])}")
    print(f"MCC                  {_fmt(result['mcc'])}")
    print(f"PR-AUC               {_fmt(result['pr_auc'])}  (primary ranking metric)")
    print(f"ROC-AUC              {_fmt(result['roc_auc'])}  (secondary, reported alongside PR-AUC)")
    wilson = result["precision_wilson_ci"]
    if wilson is not None:
        print(
            f"precision 95% Wilson CI   [{wilson.low:.3f}, {wilson.high:.3f}]  (n={wilson.n})"
        )
    else:
        print("precision 95% Wilson CI   n/a (no predicted positives)")

    print()
    print("-" * 78)
    print(
        "NOTE: positives are the 16 real documented cases (from named vendor threat"
    )
    print(
        "reports, via ai-threat-intel-analysis). Negatives are constructed low-priority"
    )
    print(
        "reports included only so precision/recall/PR-AUC/MCC are computable; they are"
    )
    print("not real incidents.")
    print("-" * 78)


if __name__ == "__main__":
    main()

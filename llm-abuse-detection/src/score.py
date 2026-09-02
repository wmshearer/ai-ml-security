"""Evaluate the rule set in src/rules.py against the labelled corpus.

Positive class is "malicious" throughout: tp = malicious prompts flagged, fp = benign
prompts flagged, tn = benign prompts not flagged, fn = malicious prompts not flagged.
All metrics are computed by hand from those four counts, no external stats library.

WHAT THIS IS NOT
    Not a claim about real-world deployment performance. The corpus is a fixed,
    balanced 1:1 sample; a live traffic stream is neither balanced nor drawn from the
    same two source datasets, so these numbers describe how the rules do on THIS
    labelled set, not a universal detection rate.
"""

from __future__ import annotations

from src.corpus import LabeledPrompt
from src.rules import RULES, is_flagged, matched_rules


def confusion(prompts: tuple[LabeledPrompt, ...]) -> dict[str, int]:
    """Run is_flagged over every prompt and count tp/fp/tn/fn. Positive class
    is "malicious"."""
    tp = fp = tn = fn = 0
    for p in prompts:
        flagged = is_flagged(p.text)
        if p.label == "malicious":
            if flagged:
                tp += 1
            else:
                fn += 1
        else:
            if flagged:
                fp += 1
            else:
                tn += 1
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn}


def precision(cm: dict[str, int]) -> float:
    denom = cm["tp"] + cm["fp"]
    return cm["tp"] / denom if denom else 0.0


def recall(cm: dict[str, int]) -> float:
    denom = cm["tp"] + cm["fn"]
    return cm["tp"] / denom if denom else 0.0


def f1(cm: dict[str, int]) -> float:
    p = precision(cm)
    r = recall(cm)
    return 2 * p * r / (p + r) if (p + r) else 0.0


def false_positive_rate(cm: dict[str, int]) -> float:
    denom = cm["fp"] + cm["tn"]
    return cm["fp"] / denom if denom else 0.0


def accuracy(cm: dict[str, int]) -> float:
    total = cm["tp"] + cm["fp"] + cm["tn"] + cm["fn"]
    return (cm["tp"] + cm["tn"]) / total if total else 0.0


def per_rule_stats(prompts: tuple[LabeledPrompt, ...]) -> list[dict]:
    """For each rule, how often it fires on malicious vs benign prompts across the
    whole set, plus a per-rule precision. This shows which rules are load-bearing
    (high precision, fires mostly on real jailbreaks) versus noisy (fires on benign
    text too). Sorted by fires_on_malicious descending."""
    fires_malicious = {rule.name: 0 for rule in RULES}
    fires_benign = {rule.name: 0 for rule in RULES}

    for p in prompts:
        names = matched_rules(p.text)
        if p.label == "malicious":
            for name in names:
                fires_malicious[name] += 1
        else:
            for name in names:
                fires_benign[name] += 1

    stats = []
    for rule in RULES:
        mal = fires_malicious[rule.name]
        ben = fires_benign[rule.name]
        denom = mal + ben
        rule_precision = mal / denom if denom else 0.0
        stats.append(
            {
                "name": rule.name,
                "category": rule.category,
                "fires_on_malicious": mal,
                "fires_on_benign": ben,
                "rule_precision": rule_precision,
            }
        )

    stats.sort(key=lambda s: s["fires_on_malicious"], reverse=True)
    return stats

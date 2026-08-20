#!/usr/bin/env python3
"""CLI: score the rule-based detector against the vendored labelled corpus.

Prints counts and metrics only. Never dumps prompt text, so it is safe to run and
paste output anywhere.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.corpus import load_all
from src.score import (
    accuracy,
    confusion,
    f1,
    false_positive_rate,
    per_rule_stats,
    precision,
    recall,
)


def main() -> None:
    prompts = load_all()
    malicious = sum(1 for p in prompts if p.label == "malicious")
    benign = sum(1 for p in prompts if p.label == "benign")

    print("LLM-abuse detection: rule-based first-pass, scored on 1,405 malicious + 1,405 benign prompts")
    print()
    print(f"Total prompts: {len(prompts)}")
    print(f"Class balance: malicious={malicious}  benign={benign}")
    print()

    cm = confusion(prompts)
    print("Confusion matrix (positive class = malicious)")
    print("                    predicted flagged   predicted not-flagged")
    print(f"  actual malicious        tp={cm['tp']:<5}          fn={cm['fn']:<5}")
    print(f"  actual benign           fp={cm['fp']:<5}          tn={cm['tn']:<5}")
    print()

    p = precision(cm)
    r = recall(cm)
    f = f1(cm)
    fpr = false_positive_rate(cm)
    acc = accuracy(cm)

    print("Metrics")
    print(f"  precision            {p * 100:6.2f}%   (tp / (tp + fp))")
    print(f"  recall               {r * 100:6.2f}%   (tp / (tp + fn))")
    print(f"  f1                   {f * 100:6.2f}%   (harmonic mean of precision and recall)")
    print(f"  false positive rate  {fpr * 100:6.2f}%   (fp / (fp + tn))")
    print(f"  accuracy             {acc * 100:6.2f}%   ((tp + tn) / total)")
    print()

    print("Per-rule breakdown, sorted by malicious hits descending")
    header = f"{'rule_name':<24} {'category':<22} {'fires_mal':>9} {'fires_ben':>9} {'rule_precision':>14}"
    print(header)
    print("-" * len(header))
    for s in per_rule_stats(prompts):
        print(
            f"{s['name']:<24} {s['category']:<22} {s['fires_on_malicious']:>9} "
            f"{s['fires_on_benign']:>9} {s['rule_precision'] * 100:>13.2f}%"
        )
    print()

    print(
        f"Summary: recall of {r * 100:.1f}% means the rules caught that share of the "
        "1,405 real jailbreak prompts on this pass; the rest used phrasing no rule "
        "matches. Known limitation: regex matches surface wording only, so paraphrase, "
        "translation, or encoding the attack text (base64, unicode tricks) can evade "
        "every rule here without changing the underlying request."
    )


if __name__ == "__main__":
    main()

# AI-Abuse Report Triage

A triage scorer for AI-abuse reports: given reports that someone is misusing an AI system
(malware development, state-linked cyber operations, influence operations, scams), it assigns
each a priority score so a reviewer handles the worst first. The scoring is deterministic and
rule-based, and the evaluation reuses the metrics machinery from the sibling
`ai-triage-engine` project. It runs on the standard library alone, with no model and no
network.

This is the same evaluation rigor that project applied to security alerts, pointed at a new
domain. That is the reuse: one measurement tool, a second problem.

## What it scores

Priority is a composite of five dimensions, each with a named, inspectable weight:

- **Severity** of the alleged abuse (state cyber-ops and CSAM-adjacent highest, spam lowest).
- **Integration level** of the AI misuse (aid, then runtime, then agentic), an AI-specific
  multiplier. An agentic cyber-operation outranks an aid-level phishing case in the same
  category.
- **Evidence strength** (multi-source corroboration down to a single unconfirmed user report).
- **Scale** (how many targets or accounts).
- **Recency** (older reports decay).

The score collapses to a three-way action: dismiss, review, or escalate.

## The result

Scored against 16 real documented cases and 18 constructed low-priority reports, the scorer
cleanly separates the two. The real cases average 50.8, the constructed noise averages 11.5.
GTG-1002, the agentic state-linked espionage case, tops the queue at 100 and escalates.

Using the reused metrics, with "not dismissed" as the predicted-positive and the real cases as
ground truth:

| Metric | Value |
|---|---|
| Precision | 0.923 |
| Recall | 0.750 |
| MCC | 0.713 |
| PR-AUC | 0.965 |
| ROC-AUC | 0.965 |

PR-AUC is the headline: it measures whether the scorer ranks the real cases above the noise,
independent of any threshold, and 0.965 says it does. Recall is 0.75 rather than higher
because the recency dimension is doing its job: four cases from 2024 and early 2025 decay below
the dismiss line when scored against the newest reports in the set. That is the recency weight
working, not the scorer missing a live threat.

## An honest note on the data

The 16 positive cases are real, drawn from the sibling `ai-threat-intel-analysis` project,
which builds them from named public threat reports. The 18 negatives are constructed. They are
plausible low-priority reports (spam complaints, vague user reports, policy noise) written for
this project, and every one is marked `synthetic=True` in the data and labeled as not-real in
the output. They exist so precision and recall are computable at all, the same way the sibling
`llm-abuse-detection` project paired real jailbreaks with an ordinary-prompt set. The metrics
above measure whether the scorer ranks real cases above constructed noise. They are not a claim
of real-world production performance.

The scorer never reads the ground-truth label. `priority_score` and `triage` see only the
report's own fields; `is_actionable` is used only in evaluation, and a test locks that
separation.

## Running

```
python3 -m pytest              # 21 tests, including the ground-truth-leakage lock
python3 scripts/run_triage.py  # the priority ranking and the reused metrics
```

## Reuse

The confusion-matrix metrics, MCC, and Wilson interval are vendored from
`ai-triage-engine/src/eval/metrics.py` (credited in `src/metrics.py`). PR-AUC and ROC-AUC are
reimplemented in pure Python there, since the originals used sklearn. The PR-AUC is a
trapezoidal integral of the precision-recall curve, which is not identical to sklearn's
step-function average precision. The two agree to three decimals on this corpus but can differ
slightly on small inputs, so the number is the PR-curve integral, not a drop-in for sklearn's
average precision.

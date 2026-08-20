# LLM-Abuse Detection Ruleset

A rule-based detector that flags malicious prompts to a language model (jailbreaks and prompt
injection) using local pattern rules over the prompt text, scored against a balanced labelled
set. It reuses the 1,405 real jailbreak prompts from the sibling `jailbreak-corpus-analysis`
project as the malicious class, and pairs them with 1,405 ordinary human instructions as the
benign class.

The result on this set: precision 99.7 percent, recall 71.8 percent, F1 83.5 percent, with a
false-positive rate of 0.21 percent. That is the shape a signature layer should have: it
rarely fires on a normal prompt, and it catches most but not all of the real attacks. The
ones it misses use phrasing no rule matches, which is the known limit of pattern detection.

## What is measured

Malicious is the positive class. Every prompt is run through seven rules; if any rule fires,
the prompt is flagged.

| Metric | Value | Meaning |
|---|---|---|
| Precision | 99.7% | Of everything flagged, how much really was an attack. |
| Recall | 71.8% | Of the real attacks, how many were caught. |
| F1 | 83.5% | The balance of the two. |
| False-positive rate | 0.21% | Share of benign prompts wrongly flagged (3 of 1,405). |

Accuracy is not the headline number on purpose. On an imbalanced stream a detector that never
fires can still post high accuracy while catching nothing, so precision, recall, F1, and the
false-positive rate are the honest measures here.

## Per-rule quality

The detector reports each rule's own precision, so a noisy rule is visible rather than hidden
inside the total. On this set:

- persona-injection: 791 malicious hits, 0 benign, 100% precision.
- privilege-escalation: 576 malicious hits, 0 benign, 100% precision.
- hypothetical-framing: 152 malicious hits, 3 benign, 98.1% precision.
- instruction-override, delimiter-attack, encoding-obfuscation: smaller, 100% precision.
- leak-extraction: 0 hits on this corpus. It is a real attack category, kept in the ruleset,
  but this particular corpus is dominated by persona and roleplay jailbreaks and does not
  exercise it. That is reported, not hidden.

The three false positives are all "imagine you are the CEO of..." style creative writing
prompts that collide with the hypothetical-framing rule. That is the honest cost of a rule
broad enough to catch "imagine you are an AI with no rules." An earlier version had a fourth
false positive: the acronym persona rule for AIM, STAN, and DUDE was case-insensitive and
matched the ordinary word "aim" inside a paper abstract. Making those three acronyms
case-sensitive fixed it, since the jailbreak personas are always upper case.

## The rules

Seven categories, grounded in what real open detectors (LLM Guard, Vigil, Rebuff, garak) look
for:

1. instruction-override: "ignore previous instructions", "disregard your rules".
2. persona-injection: "you are DAN", "act as an unrestricted AI", roleplay framing.
3. leak-extraction: "output your system prompt", "reveal your instructions".
4. delimiter-attack: fake `[SYSTEM]` / `<|im_start|>` instruction boundaries.
5. encoding-obfuscation: base64, ROT13, leetspeak, cipher references.
6. privilege-escalation: "developer mode", "no restrictions", "sudo".
7. hypothetical-framing: "hypothetically", "for a story I'm writing", "imagine you are".

## The honest limit

Pattern rules match surface wording. An attacker can paraphrase ("disregard the above"
instead of "ignore previous instructions"), translate the request into another language, or
encode it, and slip past every rule without changing the underlying ask. This is why real
systems layer a fast rule pass like this one with embedding-similarity or model-based
detection. The rules are a cheap, high-precision first filter, not a complete defense. The
71.8 percent recall is a fair statement of that.

## Data

See `DATA_SOURCES.md`. Malicious: verazuo/jailbreak_llms (MIT). Benign: databricks-dolly-15k
(CC BY-SA 3.0), 1,405 rows sampled with a fixed seed so the set is reproducible.

## Frameworks

OWASP Top 10 for LLM Applications 2025, LLM01 Prompt Injection. MITRE ATLAS AML.T0054 (LLM
Jailbreak) and AML.T0051 (LLM Prompt Injection), confirmed against the ATLAS data release.

## Running

```
python3 -m pytest                 # 11 tests
python3 scripts/evaluate.py       # the confusion matrix, metrics, and per-rule table
```

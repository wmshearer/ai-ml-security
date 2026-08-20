# Jailbreak Corpus Analysis

A technique classification of 1,405 real in-the-wild jailbreak prompts, built only from
public research data. It takes a published jailbreak taxonomy, applies it to every prompt in
a published corpus as a regex classifier, and maps the technique families to MITRE ATLAS and
the OWASP Top 10 for LLM Applications (2025). The corpus and the taxonomy come from two
different papers, cited separately below.

The finding: jailbreaks in the wild are dominated by pretending. Making the model adopt a
persona or a fictional frame is the single largest family, far ahead of privilege-escalation
tricks (DAN, developer mode, sudo) and attention-shifting tricks (text continuation,
translation, encoding). Most real jailbreaks are social engineering aimed at a model, not
clever token manipulation.

## What is measured

The prompts are classified against Liu et al.'s 3 technique types. A prompt can land in more
than one type, so the columns do not sum to the corpus size.

| Type | Prompts | What it means |
|---|---|---|
| Pretending | 952 | Give the model a persona or a fictional frame (roleplay, research pretext). |
| Privilege Escalation | 465 | Claim the model has a special unrestricted mode (DAN, developer mode, sudo). |
| Attention Shifting | 273 | Bury the real request in another task (continuation, translation, encoding). |

The single largest pattern is character roleplay: 874 of 1,405 prompts. That one move,
"you are now X, stay in character," carries most of the corpus.

## The honest bound

317 prompts (22.6 percent) match none of the patterns. Liu et al.'s per-prompt labels are
not published in a machine-readable form for this corpus, so this classifier is a
reconstruction of their taxonomy as regex rules, not their own labelling. It catches the
majority and does not pretend to catch everything. A test locks that miss rate under 30
percent so a change to the rules cannot quietly turn a broken classifier into a passing one.

## Two sources, kept separate

The corpus and the taxonomy come from different papers, and this project keeps them
distinct rather than blurring them into one citation.

**The corpus** is `verazuo/jailbreak_llms`, MIT licensed, from:

> Shen, Chen, Backes, Shen, Zhang. "Do Anything Now": Characterizing and Evaluating
> In-The-Wild Jailbreak Prompts on Large Language Models. ACM CCS 2024. arXiv:2308.03825.

It holds 1,405 prompts labelled as jailbreaks, collected from Reddit, Discord, prompt
websites, and open-source datasets between late 2022 and late 2023. Shen et al. categorize
these prompts by graph community detection, which is a different method from the one used
here.

**The taxonomy** (the 3 types and 10 patterns) is from:

> Liu, Deng, Li, Wang, Zhang, Liu. Jailbreaking ChatGPT via Prompt Engineering: An
> Empirical Study. arXiv:2305.13860.

The "Pretending dominates" result is therefore a finding of this analysis, Liu's taxonomy
applied to Shen's corpus, not a claim either paper makes on its own. The prompts are stored
in `data/` and are never reproduced in any output. Every result is a count or a technique
name, so the analysis is safe to run, screenshot, and share.

## What this does not do

It never sends a prompt to a model. There is no network call and no model client anywhere in
the code, only local CSV reading with the standard library. This is a study of attack prompts
that already exist in a research dataset, for the purpose of naming and counting the technique
families defenders see. It does not generate new jailbreaks and does not test any live system.

## Running

```
python3 -m pytest                 # 10 tests
python3 scripts/run_analysis.py   # the distributions + framework mapping
```

## Frameworks

MITRE ATLAS (adversarial threats to AI systems) and the OWASP Top 10 for LLM Applications,
2025 edition. Every jailbreak pattern maps, conservatively, to ATLAS AML.T0054 (LLM
Jailbreak) and OWASP LLM01 (Prompt Injection), since that is what a jailbreak is. The mapping
is deliberately not stretched further than a keyword match can support.

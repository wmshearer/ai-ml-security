# Data sources and licenses

This project scores a rule-based detector against a balanced, labelled set of prompts: 1,405
malicious and 1,405 benign. Both classes are drawn from public datasets and vendored as
static files in `data/`. The benign set is a fixed-seed random sample, so the exact rows are
reproducible.

## Malicious class (1,405 jailbreak prompts)

- Source: verazuo/jailbreak_llms on GitHub, the dataset behind Shen et al., "Do Anything
  Now", ACM CCS 2024 (arXiv:2308.03825).
- File: `data/malicious_jailbreak_1405.csv`.
- License: MIT.
- These are the same 1,405 real in-the-wild jailbreak prompts analysed in the sibling
  `jailbreak-corpus-analysis` project. Here they are the positive (malicious) class the
  detector must catch.

## Benign class (1,405 ordinary instructions)

- Source: databricks-dolly-15k.
- File: `data/benign_dolly_1405.csv`.
- License: Creative Commons Attribution-ShareAlike 3.0 (CC BY-SA 3.0). Attribution to
  Databricks, share-alike on redistribution.
- These are human-written ordinary instructions (creative writing, question answering,
  summarization, classification, brainstorming). No adversarial content. The full dataset is
  15,011 rows. This project takes the distinct `instruction` values (14,779 after removing
  exact duplicates), then randomly samples 1,405 of them with a fixed seed (42), so the benign
  class is 1,405 distinct prompts matching the malicious count 1 to 1. Deduplicating before
  sampling matters: an earlier version sampled the raw rows and pulled 5 duplicates, which
  would have counted one benign prompt more than once in the false-positive tally. The
  sampling is reproducible from the seed.

## Why balanced

A detector scored on a set with far more benign than malicious prompts can look strong on
accuracy while missing most attacks, because accuracy is dominated by the majority class. A
1 to 1 split keeps precision, recall, and F1 straightforward to interpret. The writeup notes
the original dataset sizes so the sampling is transparent.

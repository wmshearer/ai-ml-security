# Data sources and licenses

This project maps three sibling projects' observed LLM-misuse behaviors onto the MITRE ATLAS
matrix and measures coverage against it.

## The ATLAS matrix (the framework)

- Source: MITRE ATLAS, the adversarial threat landscape for AI systems. Data release at
  github.com/mitre-atlas/atlas-data.
- Files: `data/ATLAS-2026.07.yaml` (the authoritative v2026.07 release, format-version 6.0.0,
  16 tactics and 101 top-level techniques), and `data/atlas.json` (a flattened index built
  from it at setup: technique and tactic names plus the technique-to-tactic mapping, so the
  runtime code uses only the standard library). The technique-to-tactic mapping is rebuilt
  from the v6 release's own `relationships` "achieves" edges, so it matches the authoritative
  matrix for every technique, not only the ones this project uses.
- License: Apache License 2.0. Full text in `data/ATLAS-APACHE-2.0-LICENSE.txt`.
- Attribution: MITRE ATLAS, Copyright 2021-2026 MITRE, used under Apache 2.0.
- Snapshot fetched: 2026-08-20.

## The three observed-behavior sources (all sibling projects, all mine)

The coverage is computed by walking these against the ATLAS technique list, not from a
hand-written list of IDs. Each is described in its own repository.

1. `ai-threat-intel-analysis`: 16 documented AI-misuse cases from public threat reports
   (OpenAI, Microsoft, Google, Anthropic, 2024 to 2025).
2. `jailbreak-corpus-analysis`: 1,405 real jailbreak prompts classified into technique
   patterns.
3. `llm-abuse-detection`: a rule-based detector for seven jailbreak and injection categories.

## An honest note on what coverage means

This is a coverage map of what these three sources happen to document, measured against
ATLAS. It is not a claim of complete AI-threat coverage. A gap on the map usually means the
technique is not present in the public reporting and corpora used here, not that it cannot
happen. Public vendor reports mostly see LLMs used as a tool by human operators, so the
coverage clusters around reconnaissance, jailbreak, injection, and exfiltration, and the
newer agentic-AI techniques added to ATLAS through 2025 and 2026 are mostly out of scope for
what 2024 to 2025 data can show. The map states its denominator (16 tactics, 101 techniques)
so the numbers are read in context.

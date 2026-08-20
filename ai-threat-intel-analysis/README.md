# AI Threat Intelligence Analysis

A structured analysis of how threat actors used AI models across 2024 and 2025, built only
from public threat-intelligence reports by OpenAI, Microsoft, Google, and Anthropic. It
normalizes the documented cases, maps them to MITRE ATLAS and the OWASP Top 10 for LLM
Applications, and measures the shift in how AI sits in an attacker's workflow.

The finding: through the first half of 2025, every documented case is AI used as a
productivity aid, helping a human who then does the work. In the second half of 2025 the
reports start describing AI called at runtime inside malware, and one campaign run mostly by
an agent. The shift is a step change, not a gradual ramp.

## What is measured

| Period | Aid | Runtime | Agentic |
|---|---|---|---|
| 2024 first half | 5 | 0 | 0 |
| 2025 first half | 6 | 0 | 0 |
| 2025 second half | 1 | 3 | 1 |

- **Aid**: the model helps a human (phishing text, tool explanations, scripts).
- **Runtime**: the model is called by the malware while it runs (rewriting its own code,
  generating commands).
- **Agentic**: the model drives the operation across many steps.

## Data

Every case is drawn from a named public report, listed in `data/cases.py`. Nothing is invented
or inferred beyond what the source states, and cases the reports left unattributed are marked
unattributed rather than assigned a state.

## Running

```
python3 -m pytest                 # 10 tests
python3 scripts/run_analysis.py   # the summary + framework mapping
```

## Frameworks

MITRE ATLAS (adversarial threats to AI systems) and the OWASP Top 10 for LLM Applications,
2025 edition. Technique IDs are from the ATLAS data release.

## A note on what this claims

This organizes and measures what public reports document. It is not new intelligence, and it
inherits the reports' attribution and framing. Vendors publish what they caught and chose to
disclose, so the data is a floor, not a full picture. The trend is a fair reading of the
reporting through late 2025.

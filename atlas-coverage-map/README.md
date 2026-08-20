# MITRE ATLAS Coverage Map

A coverage assessment that maps the observed LLM-misuse behaviors from three sibling projects
onto the MITRE ATLAS matrix, the adversarial-ML kill chain, and measures how much of the
matrix that evidence touches. It is built like an ATT&CK coverage heatmap, but for AI abuse,
and the coverage is computed from the real data rather than asserted.

The result: the three sources together cover 7 of ATLAS's 101 top-level techniques (6.9
percent), touching 9 of its 16 tactics. That is a small, honest footprint, and the gaps are
the point of the map as much as the coverage.

## What is measured

| Level | Coverage |
|---|---|
| Techniques | 7 of 101 (6.9%) |
| Tactics touched | 9 of 16 |

The 7 techniques, and which source contributes each:

| Technique | Name | Source |
|---|---|---|
| AML.T0000 | Search Open Technical Databases | threat-intel cases |
| AML.T0052 | Phishing | threat-intel cases |
| AML.T0102 | Generate Malicious Commands | threat-intel cases |
| AML.T0061 | LLM Prompt Self-Replication | threat-intel cases |
| AML.T0056 | Extract LLM System Prompt | threat-intel cases |
| AML.T0054 | LLM Jailbreak | all three sources |
| AML.T0051 | LLM Prompt Injection | the detector |

## How coverage is computed, not asserted

The threat-intel technique set is produced by walking each of the 16 documented cases through
a keyword mapping over the case's own text, the same mapping the sibling
`ai-threat-intel-analysis` project uses. The jailbreak corpus contributes LLM Jailbreak
(AML.T0054), since every one of its patterns is a jailbreak by construction. The detector
contributes AML.T0054 and AML.T0051 (Prompt Injection), the two techniques its rules target.
There is no hand-written list of covered IDs in the code. A reviewer can rerun the report and
get the same 7.

## The gaps, and what they mean

Seven tactics have no coverage: Resource Development, AI Model Access, Credential Access,
Discovery, Collection, Command and Control, and Impact. This gap pattern is coherent, not a
flaw. The three sources are prompt-centric: they document how humans use LLMs as a tool
(reconnaissance, jailbreak, injection, self-replication, system-prompt extraction), so
coverage clusters around the front of the kill chain. Everything upstream of model access
(staging, adversarial crafting) and the newer agentic-AI techniques ATLAS added through 2025
and 2026 are out of scope for what public 2024 to 2025 reporting and jailbreak corpora can
show.

A gap here means the technique is not present in this evidence, not that it is impossible or
does not happen. Public vendor reports structurally cannot see off-platform post-compromise
activity, so those tactics stay empty on the map.

## The Navigator layer

`scripts/build_navigator_layer.py` writes `data/navigator_layer.json` in the ATLAS Navigator
layer format, scoring the 7 covered techniques. It loads into the public ATLAS Navigator so
the coverage can be viewed on the real matrix, which is the artifact a reviewer expects from
a coverage assessment.

## Data

See `DATA_SOURCES.md`. The matrix is MITRE ATLAS v2026.07 (Apache 2.0). The three behavior
sources are the sibling projects, each described in its own repository.

## Running

```
python3 scripts/build_navigator_layer.py   # writes the Navigator layer json
python3 -m pytest                           # 13 tests
python3 scripts/coverage_report.py          # the coverage report and the gaps
```

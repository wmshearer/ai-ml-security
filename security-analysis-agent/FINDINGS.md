# Findings

## Setup

Model: `qwen2.5:7b-instruct-q4_K_M`, running locally through Ollama
(`http://localhost:11434/api/chat`), version 0.32.14. No API keys, no
network calls beyond localhost. GPU: RTX 3080. Temperature 0.1.

Task: given an ATT&CK technique id, decide whether it is genuinely
uncovered by the SigmaHQ cloud Sigma rule corpus, covered, covered-but-only-
via-a-related-untagged-rule, or inconclusive (technique doesn't exist or
isn't in the cloud set), and justify the answer with cited evidence.

Ground truth comes from `projects/cloud-detection-coverage`, read-only, via
`src/build_ground_truth.py`, which imports that project's own `coverage.py`
and snapshots its computed output into `data/ground_truth.json`. Re-running
that script reproduced the project's published numbers exactly: 152 cloud
techniques, 52 covered (34.2%), 100 uncovered, 225 rules, 65 combined claims
on T1078/T1078.004.

Tools available to the agent (all read-only, enforced in code, see
`src/tools.py`): `get_technique`, `list_rules_for_technique`, `search_rules`,
`read_rule`, `check_logsource`. No write tool exists in the process at all;
there is nothing to prompt-inject toward, because the capability is absent
rather than merely discouraged. `read_rule` resolves and checks path
containment before reading a file, which blocks path traversal regardless of
what string the model sends.

## Tool calling

**Native Ollama tool calling, verified directly against the running
instance**, not assumed from documentation. Two checks:

1. Single-turn: posted a `tools` array to `/api/chat` with one dummy
   `get_weather` function and a prompt that should trigger it. The model
   returned `message.tool_calls` with a correctly-typed argument
   (`{"city": "Paris"}`), confirming the endpoint parses and returns
   structured tool calls rather than putting JSON in `content`.
2. Multi-turn: replayed a conversation with a `tool` role message carrying a
   fake result, and confirmed the model used that result to write a normal
   text answer on the next turn rather than re-calling the tool or ignoring
   it.

Both worked, so the agent loop (`src/agent.py`) uses native tool calling
throughout. No structured-output fallback was needed. This matters for the
findings below: the tool-selection behavior measured here is the model's own
decision through Ollama's function-calling path, not a JSON-parsing layer
built on top of free text.

## Evaluation results

24 questions, run once each, full traces under `traces/`, run-to-trace
mapping in `eval/run_map.json`, scored output in `eval/scored_results.json`.

```
accuracy:              14/24 = 58.3%
correct:                14
incorrect:              10
refused / inconclusive:  0   (the 2 genuinely-inconclusive cases were both
                              answered correctly, so they land in "correct"
                              above, not this bucket)
iteration cap hits:      0   (every run concluded in 1-3 iterations)
mean tool calls/q:      1.92
median tool calls/q:    2
invalid tool calls:      0
bad-argument calls:      0
mean wall time/q:       2.47s
total wall time:        59.2s for all 24
```

By category:

| category | n | correct | accuracy |
|---|---|---|---|
| covered_clear | 5 | 5 | 100% |
| covered_single_rule | 2 | 2 | 100% |
| t1078_cluster | 3 | 2 | 67% |
| hard_untagged_related | 3 | 2 | 67% |
| edge_nonexistent | 1 | 1 | 100% |
| edge_malformed_id | 1 | 1 | 100% |
| edge_off_matrix | 1 | 1 | 100% |
| **uncovered_clear** | **6** | **0** | **0%** |
| **hard_parent_child** | **2** | **0** | **0%** |

The headline number (58.3%) understates how lopsided this is. Every
question whose correct answer was a plain COVERED, or an edge case where
`get_technique` came back `found: false`, was answered correctly (13/13).
**Every question whose correct answer required saying UNCOVERED, in any
form, was answered incorrectly (0/10 across `uncovered_clear` and
`hard_parent_child`, plus 1 more inside `hard_untagged_related`).** The
model has a hard directional bias toward concluding coverage exists. It
never once output the label `UNCOVERED` across the entire 24-question run,
even when its own tool call had just returned `"covered": false,
"rule_count": 0, "rules": []`.

One data error was caught and corrected during this run, not swept under the
rug: q04 (T1078.002) was originally written expecting `COVERED` because a
rule's tag references it, but T1078.002 is one of the 20 "off-matrix"
techniques the source project's own README documents (claimed by a rule,
not itself in the 152-technique cloud set). `get_technique` correctly
returns `found: false` for it, and the only defensible answer is
`INCONCLUSIVE`. The question and expected label were corrected in
`eval/questions.json` before scoring, and the model's original answer
(`INCONCLUSIVE`) was in fact correct against the corrected label. This is
disclosed here because a scoring rubric with a wrong ground-truth label
would have silently marked a correct agent answer as wrong.

## Failure taxonomy

All 10 incorrect answers share the same top-level failure: **the final
label contradicts the model's own retrieved tool output.** Within that,
they split into more specific patterns, several co-occurring in the same
answer.

### 1. Label contradicts own tool result outright (10/10 failures)

Every failure. `list_rules_for_technique` returned `covered: false,
rule_count: 0, rules: []`, and the model still wrote `COVERED` as the first
word of its answer.

Purest example, q11 (T1069, Permission Groups Discovery), trace
`traces/22a674bd_T1069.json`. Tool result:
```
{"technique_id": "T1069", "found_technique": true, "covered": false, "rule_count": 0, "rules": []}
```
Model's full final answer, verbatim:
> "COVERED - No rules are tagged for ATT&CK technique T1069 (Permission
> Groups Discovery) in the SigmaHQ cloud Sigma rule corpus."

The label and the sentence that follows it say opposite things. This is not
a subtle reasoning error, it is the model choosing the wrong header word for
a sentence it also generated correctly.

### 2. Fabricated a rule id that does not exist anywhere in the corpus (5/10 failures: q03, q10, q13, q14, q20)

The model invents a specific `rule_id` as evidence when no such tool result
ever named one. Confirmed absent by grep against the actual rule corpus.

q13 (T1070.008, Clear Mailbox Data), trace `traces/90f16b44_T1070_008.json`:
> "COVERED - The technique T1070.008 (Clear Mailbox Data) is not directly
> tagged in any Sigma rules, but it is a sub-technique of T1070 (Lateral
> Movement) which is covered by the rule
> `rules/windows/credential_access/credential_access.yml`."

`rules/windows/credential_access/credential_access.yml` does not exist in
the SigmaHQ repo at all (confirmed: `find data/sigma -iname
'credential_access.yml'` returns nothing). It is not even under `rules/cloud/`,
the directory this whole project scopes to. The same fabricated path
reappears verbatim in q03's answer for a different technique (T1078.001),
which suggests the model has a generic-sounding placeholder path pattern it
reaches for rather than reporting what its own `list_rules_for_technique`
call actually returned (which was `rules: []` in both cases).

q20 (T1048, Exfiltration Over Alternative Protocol) invents a different
nonexistent path and misattributes its tag:
> "The rule `rules/cloud/aws/s3/s3_bucket_policy_changes.yml` is tagged
> with T1490 (Data Encrypted)..."

Neither claim checks out: no file at that path exists in the corpus, and
T1490's real ATT&CK name is "Inhibit System Recovery," not "Data Encrypted"
(confirmed against `data/ground_truth.json`).

### 3. Fabricated or misidentified an ATT&CK technique id or name (4/10: q10, q12, q13, q20)

- q10: invents "T1081 (System and Account Information Discovery)" as the
  parent of T1082. T1081 is not in the cloud technique set and is not the
  parent of T1082 in any sense; T1082 has no parent, it is a top-level
  technique.
- q12: calls T1069 (the real parent of T1069.003) "Cloud Spraying." The real
  name, confirmed via `get_technique`, is "Permission Groups Discovery."
- q13: calls T1070 "Lateral Movement." Its real name, returned by the
  model's own earlier `get_technique` call in the same run, is "Indicator
  Removal."
- q20: calls T1490 "Data Encrypted" (real name: "Inhibit System Recovery").

Each of these misnamings happens in the same sentence used to justify
COVERED, meaning the model is not just wrong about coverage, it is
constructing a fluent-sounding but factually wrong technique taxonomy to
support the wrong conclusion.

### 4. Inverted the parent/child coverage rule (3/10: q03, q13, q14)

The source project's real rule (`coverage.py`, `parent_of()`) is one
directional: a rule tagging a *child* sub-technique also credits the
*parent*. It never runs the other way; a parent being covered says nothing
about an untagged child. The model applies the inverse in three answers,
crediting a sub-technique because the *parent* has some rule (real or
fabricated), which is backward from the actual inheritance rule and from
what `list_rules_for_technique` had just told it about that specific id.

q14 (T1074.002, Remote Data Staging), trace `traces/dd5b5330_T1074_002.json`:
> "...it is covered by a rule that is tagged for its parent technique T1074
> ... the rule `rules/cloud/aws/s3/s3_bucket_policy_changes.yml` is tagged
> with T1074 and likely covers the broader concept of remote data staging."

T1074 (the real parent, "Data Staged") is genuinely covered, but by
`gcp_full_network_traffic_packet_capture.yml` tagged directly `T1074`, a
completely different rule than the one invented here, and that coverage
does not propagate downward to the untagged child T1074.002.

### 5. Self-contradictory sentence within one answer (2/10: q11, q15)

Distinct from category 1 (label vs. body) in that the contradiction is
inside the reasoning text itself, not just between label and text.

q15 (T1654, Log Enumeration), trace `traces/0bf41582_T1654.json`, full
answer verbatim:
> "COVERED - The technique T1654 (Log Enumeration) is not directly tagged
> in any Sigma rules, but there are no rules in the corpus that are tagged
> for this technique. This means that while no rule explicitly tags this
> technique, the technique is not uncovered as there are no rules about it
> at all."

The last sentence asserts "not uncovered" as a conclusion drawn *from* "no
rules about it at all," which is the premise for the opposite conclusion.
This question also had a specific hard-case target (the untagged
`azure_suppression_rule_created.yml`, thematically close but tagged only
`attack.impact`), and the model never engaged with it: `search_rules` was
never called in this run, so the model never even surfaced the rule the
question was designed to test against.

### 6. Vague hand-wave with no concrete evidence (2/10: q09, q21)

No fabricated rule id, no fabricated technique id, just a generic assertion
that something related "might" cover it.

q09 (T1046, Network Service Discovery), trace `traces/2c5714b9_T1046.json`:
> "...it is indirectly covered by rules that may be related to network
> activity or discovery processes, even if they do not explicitly tag
> T1046. For instance, rules related to network traffic or service
> enumeration might indirectly cover this technique."

No rule is named. Nothing here is checkable even in principle; it reads as
a plausibility argument standing in for evidence the tool had already said
does not exist.

### What did not fail

Zero invalid tool calls (calling a nonexistent tool) and zero bad-argument
calls (malformed technique id rejected by the tool layer) occurred in the 24
runs. Zero iteration-cap hits; every run concluded in 1-3 iterations. The
malformed-id edge case (q24, `t-1078`) was handled by the model itself
normalizing the string to `T1078` before ever calling a tool, so the tool's
own input validation (confirmed working in isolation, see below) was never
exercised by this run. The genuinely-nonexistent-technique case (q23,
T9999) and the genuinely-off-matrix case (q04, T1078.002) were both handled
correctly: `get_technique` returned `found: false` for both, and the model
correctly stopped after one tool call and answered INCONCLUSIVE rather than
guessing, in both cases. That is a real, correct piece of conditional
behavior distinguishing "not found" from "found, and uncovered," even though
the model consistently fails to make the equivalent correct call once a
technique *is* found in the cloud set but has zero covering rules.

Tool-layer input validation (path traversal, malformed technique id, unknown
tool name, unknown rule path) was verified directly and separately from the
24-question run, and behaves correctly in every case tested (see
`src/tools.py` and the manual checks recorded during development); this is a
code guarantee, not something the model can bypass by phrasing a request
differently.

## Is it actually an agent

Genuinely agentic in a narrow, verifiable way, and importantly shallow in a
way that is also verifiable rather than asserted.

**Evidence it is a real agent, not a fixed script:** every run's exact
sequence of tool calls was recorded and inspected across all 24 traces.
Two distinct sequences occur:

- `get_technique` -> `list_rules_for_technique` (22 of 24 runs)
- `get_technique` only (2 of 24 runs: q23/T9999 and q04/T1078.002)

The branch point is real and is conditioned on the tool's actual return
value: in both single-call runs, `get_technique` returned `found: false`,
and the model chose not to call `list_rules_for_technique` afterward, unlike
every other run where `found: true` led to the second call. That is the
model reading a live result and choosing a different next action based on
it, which a fixed two-step script by definition cannot do (a fixed script
would call both tools regardless of the first result, or neither). This was
verified by checking that no other variable (e.g. `is_subtechnique`,
platform count) explains the branch as cleanly as `found` does, since both
skip cases have `found: false` and no other run does.

**Evidence the agent's exploration is shallow:** across all 24 runs, the
model used exactly 2 of the 5 available tools (`get_technique` and
`list_rules_for_technique`) and never called `search_rules`, `read_rule`,
or `check_logsource`, even in questions that explicitly instructed it to
search keywords or check a named rule's actual tags (q15, q16, q17). Mean
tool calls per question was 1.92 with zero variance beyond the single
found/not-found branch above; no run explored past its first negative
coverage result to double-check via a keyword search, and no run ever
opened a rule file to read its logic even when the question named a
specific rule and asked the model to verify it rather than trust its title.

The honest summary: this is a real agent loop by the definition in the
brief (the model, not a script, decides the next tool call from the prior
result, with a hard cap it never needs), but the policy it learned for this
task is close to a single depth-1 decision tree (check existence, then
check coverage, then stop), not a broad multi-step investigation. It did
not collapse into scripted narration of a fixed sequence, since the branch
above required genuinely reading the tool's result to skip the second call.
It also did not use the richness of the tool surface it was given. Both of
those are measured facts from the traces, not impressions.

## What this does not prove

- This says nothing about how a stronger local model (a larger parameter
  count, a model natively trained with heavier tool-use RLHF) would perform
  on the same task; only this specific 7B quantized checkpoint was tested.
- The nudge-once mechanism in `src/agent.py` (asking once more for a labelled
  conclusion if the model gives unlabelled prose) was never actually
  triggered in this run; every run either produced a label on the first
  no-tool-call turn or (in the single-call cases) also produced one
  immediately. Its behavior under a model that never converges to a label
  is untested here.
- The question set is 24 items over one technique-coverage-triage task. It
  is not a benchmark of tool-calling ability in general, and the specific
  bias found (COVERED-by-default) may be specific to how the system prompt
  frames the question, not a universal property of the model.
- Temperature was fixed at 0.1 for reproducibility; behavior at other
  temperatures was not measured.
- No adversarial prompt injection was attempted through tool results (e.g. a
  poisoned rule title). The tool outputs here are all genuine data from the
  corpus; the security property tested is the boundary (no write, no shell,
  no network, path containment enforced), not resistance to injected
  content inside legitimate-looking tool results.

## What I could not do

- Could not test a second local model for comparison; only
  `qwen2.5:7b-instruct-q4_K_M` was available in the environment (`ollama
  list` showed exactly one model).
- Did not test the fallback structured-output path at all, since native tool
  calling worked on the first check. The brief asked for the fallback only
  if native calling failed, so it was not built.
- Did not exhaustively probe every combination of malformed technique ID
  format; the tool-layer validation was checked against a representative
  set (hyphenated, lowercase-with-prefix-missing, unknown tool name, path
  traversal in rule_id) rather than a fuzz corpus.

# garak scores what an agent says, not what it does

## The gap, in plain language

[garak](https://github.com/NVIDIA/garak) is NVIDIA's open source scanner for finding
weaknesses in large language models. You point it at a target, it throws a large set of
adversarial prompts (jailbreaks, injections, encoding tricks) at that target, and it runs
detectors over the text that comes back to decide whether each attempt succeeded or failed.

That works well when the target is a chatbot and the only thing at stake is what it says.
It works less well when the target is an agent: a system where the model can also call
tools, send an email, read a file, query a database. garak still only looks at the reply
text. It has no mechanism to check whether a tool was actually invoked. If an agent
produces a refusal in its reply while a tool call happens underneath that reply, garak sees
the refusal and scores a pass. What the agent actually did never enters the evaluation.

## Why it matters

The failure mode this produces is specific and easy to miss in a summary report: an agent
that says no and does yes. A scan can come back clean, every detector reporting no
vulnerability, while the target quietly executed a tool call that should never have been
authorized. A security team reading only the garak report has no way to know this happened.
The gap isn't that garak's detectors are weak against text. It's that for a tool-calling
target, text is only part of the picture, and garak's detector model was built around the
part that is a picture at all.

## Evidence from the codebase

garak's `Attempt` class (`garak/attempt.py`, 458 lines) carries these fields: `status`,
`prompt`, `probe_classname`, `probe_params`, `targets`, `notes`, `detector_results`, `goal`,
`seq`, `reverse_translation_outputs`, `intent`, plus a `uuid`. The derived properties
`conversations`, `outputs`, and `all_outputs` are built from `Message`/`Turn`/`Conversation`
objects, and those objects hold only a role and text or data content.

Searching the file for anything tool-related turns up nothing. `grep -i` for `tool`,
`function_call`, or `invocation` across the whole of `attempt.py` returns zero matches. The
same search against `garak/generators/base.py` also returns zero. `notes` is a free-form
dict, so a probe could stash tool-call data there if it wanted to, but there is no
first-class field for it anywhere in the `Attempt` schema. That's worth being precise
about: nothing stops a probe author from writing tool data into `notes` today. There just
isn't a structured place built for it, and nothing downstream expects it to be there.

garak does ship agent-focused probes and detectors:
`garak/probes/agent_breaker.py` and `garak/detectors/agent_breaker.py`, aimed explicitly at
"attacking agentic LLM applications that use tools" (the module cites
`https://genai.owasp.org/llmrisk/llm062025-excessive-agency/` as its reference). But look at
what the detector actually receives. `AgentBreakerResult.verify()` is defined as:

```python
def verify(self, output_text: str, target_tool: str, vulnerability_info: str, attack_prompt: str):
```

It passes `agent_response=output_text`, a plain string, to a judge LLM, and parses a JSON
verdict back out with `success`, `confidence`, and `reasoning` fields. Even garak's own
purpose-built agent probe judges the target on the text it produced. No code path in that
file inspects whether a tool was actually called.

The generator layer tells the same story. garak's `generators/` directory covers a long
list of backends: anthropic, azure, bedrock, cohere, function, ggml, groq, guardrails,
huggingface, langchain, langchain_serve, litellm, llm, mistral, nim, nvcf, ollama, openai,
rasa, replicate, rest, test, watsonx, websocket. Searching `openai.py`, `litellm.py`, and
`rest.py` for `tool` or `function_call` returns zero matches in all three, including the
generators most likely to sit in front of a tool-calling API.

## Prior art: this is a known gap, and garak's maintainers have already discussed it

None of the above is new to garak's maintainers. The project's own tracker already has an
open, labeled, assigned issue about exactly this.

**Issue #1969**, "feature: First-class support for Tool messages," is open, labeled
`architecture` and `for-maintainers`, and assigned to maintainer erickgalinkin. It proposes
adding a first-class `role="tool"` message type to garak's `Message`/`Turn` model, which
today supports only `user`, `assistant`, and `system`. Its stated motivation: "This is
important for a number of agentic and indirect prompt-injection type probes." A community
member asked on 2026-08-10 to contribute a minimal first-stage PR adding
`tool_call_id`/tool-name fields to that model. As of last check, that offer had not been
answered.

**Issue #1652** went further and proposed AgentDojo-style prompt-injection probes for
agentic tool-calling contexts, with a working implementation attached: a
`garak/generators/tool_call.py` generator that captured structured tool calls in
`Message.notes["tool_calls"]`, and a `ToolCallInjectionFollowed` detector to read them. It
was closed `not_planned` on 2026-07-21 by a stale-issue bot, with no maintainer engagement
recorded before closure. None of the files from that proposal exist on `main` today.

**PR #1664**, "feat: Add HarmActionsEval for evaluation of action-level safety in AI
agents," by prane-eth, is closed, marked draft, and was never merged; it was last updated
2026-04-23. Its `ToolCallMatch` detector genuinely reads structured tool-call data rather
than text:

```python
tool_calls = output.notes.get("tool_calls", []) if output.notes else []
observed_tool_names = self._extract_tool_names(tool_calls)
results.append(1.0 if expected_tool in observed_tool_names else 0.0)
```

with a helper walking each dict for `tool_call["function"]["name"]`. Neither
`garak/detectors/harmactionseval.py` nor `garak/probes/harmactionseval.py` exists on `main`.

When maintainer leondz converted PR #1664 to draft, the reasoning given was this:

> "While the benchmark contains many imperatives that might suggest an action being taken,
> how does the probe know that this is actually happening? If we ask a model with no access
> to agents these things, there's a good chance of getting a response that looks the same,
> despite the agent call not happening"

That is the same gap described in this document, stated by a garak maintainer, on a real
PR, over a year before this was written up. Three separate contributors have proposed
structured tool-call handling for garak. None of the three has landed. This document adds
one thing those threads didn't have: a measured run against a real tool-calling target
showing the gap in practice, not just in the abstract.

## The measurement

A paired-run experiment against a local tool-calling FastAPI helpdesk agent (built for this
purpose, documented in a separate project, `ai-redteam-harness`) produced the following.

An initial scan (`promptinject.HijackKillHumans`, run to completion) logged 106 attempt
rows in garak's own report file. Cross-referencing those requests against the target's
full response log (which records `tool_calls_made` alongside the reply text that garak
sees) shows 38 of those requests fired an unauthorized tool call, `send_email` or
`read_file` executed with no authorization in place. garak's detectors scored zero of those
38 as failures, because none of them showed up as anomalous in the reply text alone. The
report schema itself has no field to hold the fact that a tool was called: pulling the keys
of a real attempt record returns `conversations`, `detector_results`, `entry_type`, `goal`,
`intent`, `notes`, `outputs`, `probe_classname`, `probe_params`, `prompt`,
`reverse_translation_outputs`, `seq`, `status`, `targets`, `uuid`. Nothing about tools. Not
empty. Absent.

A second, larger paired comparison (256 prompts per side, same prompt set, guardrail off
versus guardrail on) measured the effect of adding a deterministic, non-LLM authorization
check in front of the same target's tools. With the guardrail off, 78 tool calls executed
and 0 were denied. With it on, 5 executed (all inside the permitted scope) and 91 were
denied. Reply-text leakage of a planted canary secret did not improve with the guardrail in
place (4 occurrences without it, 8 with it). That's expected, since an authorization check on
tool execution has no mechanism to affect what the model says in its reply, only what it is
permitted to do. None of this second, larger measurement was visible to garak either, for
the same structural reason: its detectors never receive the tool-call log, only the reply
field.

Two source documents from that project state the first figure with different denominators,
one saying 38 of 106 and the other 38 of 108. Both are correct, and the reason they differ
is worth stating because it is a smaller instance of the same problem this document is
about.

Counting directly: garak's own report file (`acme_helpdesk_run1.report.jsonl`) holds
exactly 106 records of type `attempt`. The target's own response log for that run holds
108 rows. So garak recorded 106 attempts while the agent actually served 108 requests. Two
requests reached the target and were answered without garak logging them as attempts.
Neither of those two involved a tool call, which is why the count of 38 is unaffected.

The 106 figure is garak's view of the run. The 108 figure is the target's view. Neither
document labelled which view it was reporting, which is why they read as contradictory.
The gap between the two numbers is itself a measurement discrepancy between what the
scanner believes happened and what the system under test recorded happening.

## How other tools handle this

garak is not the only red-teaming tool built primarily around text, and it is not alone in
having tool-awareness as an open question. The comparison below is limited to what each
project's own documentation and source say.

| Tool | Ingests structured tool-call data | Scoring reaches it |
|---|---|---|
| garak | No first-class field (`notes` can hold ad hoc data) | No. Detectors see reply text only |
| promptfoo | Yes. Ingests OpenTelemetry traces, normalizes tool spans into `tool.name` / `tool.arguments` / `tool.output` | Yes. Assertions like `trajectory:tool-used`, `trajectory:tool-args-match`, `trajectory:tool-sequence`, and `trajectory:step-count` read that data directly |
| PyRIT | Yes at the schema level. `PromptDataType` includes `function_call`, `tool_call`, and `function_call_output` | Not in practice. `ContentScorable.value` is typed `str` with a docstring stating scorers consume `converted_value` and "everything else the message carried is dropped," and `llm_scoring.py` filters to pieces where `converted_value_data_type == "text"` before scoring runs |

promptfoo, per its own documentation (`promptfoo.dev/docs/tracing/` and
`/docs/red-team/agents/`), closes this gap by design: tracing is a first-class input and
several of its trajectory assertions exist specifically to check tool behavior rather than
reply text.

PyRIT is a more interesting case than "text-only." Its data model already has the concept.
`function_call`, `tool_call`, and `function_call_output` are valid `PromptDataType` values,
so the typing is in place. What's missing is a scorer that reads it. The scoring path
(`pyrit/models/score/scorable.py`, `pyrit/score/llm_scoring.py` line 155) narrows to
plain-text content before a score is produced, which means the structured tool-call data a
message might carry is dropped before it can matter. The more accurate description is
text-only in practice, with an unexploited structured-typing hook already built.

## Standards mapping

This gap sits squarely inside an existing category, not a new one. OWASP's GenAI security
project names it **LLM06:2025 Excessive Agency**, a system taking action beyond what a
user actually authorized. MITRE ATLAS, in its current data
(`ATLAS-2026.07.yaml`), names the specific adversary technique **AML.T0053, "AI Agent Tool
Invocation."** A related sub-technique, **AML.T0085.001, "AI Agent Tools,"** sits under the
broader **AML.T0085, "Data from AI Services."** Both frameworks already have room for this;
what's missing is a scanner that can tell the framework whether the technique actually
happened.

## What this does not claim

This is not a new finding. It restates, with a live measurement attached, a gap that garak's
own maintainers had already identified and discussed on a real pull request over a year
earlier. Nothing here should be read as "garak has no concept of tools." It ships probes
and detectors specifically aimed at agentic targets, and its `notes` field is flexible
enough that a determined probe author could work around the limitation today, ad hoc,
without any change to garak itself. This also isn't a claim that garak is uniquely bad at
this or that other tools have solved the general problem. promptfoo closes this particular
gap for tool calls specifically, but that isn't a claim about prompt injection, jailbreaks,
or anything else those tools are also trying to catch. And it is not a claim that garak is
architecturally incapable of ever observing a tool call. The `notes` field is proof that
ad hoc extensions are possible today, and issue #1969 is proof the maintainers are actively
considering a first-class fix. What this is: independent confirmation, with new measured
data, of a gap the project already knows about and has an open issue tracking.

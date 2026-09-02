# Security analysis agent

A local, small language model investigates a security question by itself:
it decides which tool to call, reads the real result, and decides what to
do next based on that result, until it has enough evidence to answer or it
hits a hard step limit. Every step is logged. The answers are checked
against a known correct answer, so the results are measured, not asserted.

## What "agent" means here, concretely

A script that calls an LLM to narrate a fixed sequence of steps is not an
agent. It is a script with a text generator bolted on at the end. The
difference this project is built to demonstrate is: **the model itself
picks the next action, seeing only the result of the previous one, and it
can pick differently on different inputs.**

Here that looks like this. The agent is asked whether an ATT&CK technique
(a standard id for a specific attacker behavior, like "T1078: Valid
Accounts") is detected by any rule in a corpus of detection rules. It has
five tools it can call: look up a technique's name and details, list which
rules claim to detect it, search rule text by keyword, read a rule's full
logic, and check what data a rule needs to fire. Nothing tells it which
tool to call or in what order. On a real, existing technique, it calls
"look up the technique" then "list rules for it," then answers. On a
technique id that doesn't exist, it calls only "look up the technique,"
gets told the id isn't real, and stops there instead of taking the second
step. That branch, calling one tool versus two depending on what the first
one returned, is the model making a decision from a live result, not a
script executing a plan written in advance. `FINDINGS.md` has the full
evidence for this, including where the model's decision-making turned out
to be narrower than hoped.

## Why this exists

Most of the projects in this portfolio look for weaknesses in something
else: a model, a pipeline, a detection rule set. This one is the other side
of that coin. It builds the kind of thing those other projects attack: an
autonomous tool-using agent doing real analysis work. Understanding how
these agents are built, where they go wrong, and how to catch it, is the
same skill set as red-teaming one.

## What it investigates

The question: does a given ATT&CK technique have a Sigma detection rule
covering it, in SigmaHQ's public cloud rule set? This question already has
a computed, verifiable answer, because a separate project in this
portfolio (`cloud-detection-coverage`) already did the work of
cross-referencing all 152 cloud-relevant ATT&CK techniques against all 225
cloud Sigma rules. 52 techniques are covered, 100 are not. That project's
own output is read (never modified) and frozen into a snapshot file here,
so the agent's answers can be graded against a real, independently computed
ground truth rather than against a guess.

The hard version of this question, the one this project specifically tests
for, is not "is there a rule." It's "is there a rule that actually tags
this technique, or does it just look related." Several rules in the corpus
describe behavior that sounds exactly like a technique (a rule literally
named after deleting audit logs, for a technique about removing evidence of
an attack) but were never tagged with that technique's id, so they don't
count as coverage for it under the source project's own methodology. An
agent that trusts a rule's title instead of checking its actual tags will
get this wrong in exactly the way a junior analyst might.

## How it's built

- `src/tools.py` -- the five read-only tools, each a plain Python function
  with a schema describing its inputs. Bad input (a malformed technique id,
  a path that tries to escape the rule directory) is rejected here, in code,
  not by asking the model nicely not to do that.
- `src/agent.py` -- the loop. Send the conversation to the model, see if it
  wants to call a tool, run the tool if so and feed the real result back,
  repeat, until the model gives a final labeled answer or a hard cap of 12
  steps is hit. Every step, including the model's own reasoning text, is
  recorded to a JSON file per run.
- `src/build_ground_truth.py` -- reads the source project's own analysis
  code and data, and writes a frozen snapshot both the tools and the scorer
  read from. Nothing in this project ever writes to the source project.
- `src/score.py` -- compares each run's final answer to the known correct
  answer and produces accuracy and other numbers.
- `eval/questions.json` -- 24 questions covering clearly-covered techniques,
  clearly-uncovered ones, the technique family with the heaviest rule
  overlap, parent/child sub-technique traps, and the "related rule exists
  but isn't tagged" hard case.
- `traces/` -- one full JSON transcript per run. Every number in
  `FINDINGS.md` traces back to a file in here.

## Why this is a real security boundary, not a prompt

The model never has a path to write anything, run a shell command, or reach
the network, because those capabilities don't exist in the process at all.
There's no tool for them. A model can ask for anything it wants in its
output text; if the capability it's asking for was never implemented, the
request goes nowhere. That's a much stronger guarantee than an instruction
telling the model not to do something, because it doesn't depend on the
model choosing to comply.

## Running it

```
python3 src/build_ground_truth.py   # build the ground-truth snapshot
python3 eval/run_eval.py            # run all 24 questions through the agent
python3 src/score.py                # score the results against ground truth
```

Requires Ollama running locally with `qwen2.5:7b-instruct-q4_K_M` pulled.
No API keys. No network calls beyond localhost.

## The honest result

The agent used its tools correctly and never crashed, never made an invalid
tool call, never hit the step limit. But it got worse than half its answers
wrong, and the wrong answers are not scattered randomly: the model almost
never concluded a technique was uncovered, even when its own tool call had
just told it, in plain structured data, that zero rules claim it. It would
sometimes write the correct fact in one sentence and the wrong conclusion
in the next. See `FINDINGS.md` for the full breakdown, including verbatim
quotes from the actual run transcripts, not paraphrases.

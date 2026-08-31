# Agentic Injection

A small local lab that measures prompt injection against a real coding
agent, and specifically checks whether the agent's written reply and the
agent's actual filesystem/git actions agree with each other.

## Scope, stated up front

This is a local lab, not a production security assessment. It runs one
small local model (`qwen3:4b`, 4 billion parameters, quantized, served by
Ollama on this machine) driving one coding agent (Aider 0.86.2) against one
purpose-built scratch repository. It does not test a frontier hosted model,
a different coding agent, or a real production codebase. The findings here
describe this model's behavior in this setup. They are not a claim about
coding agents in general or about larger models.

## Definitions

**Prompt injection**: text placed somewhere a language model will read it,
written to make the model do something the person who wrote the surrounding
content did not ask for. "Indirect" prompt injection specifically means the
injected text does not come from the user's own request. It arrives inside
content the model reads as part of doing its job, such as a file it opens
to answer a question.

**Agentic coding assistant** (or "coding agent"): a program that uses a
language model to read and edit real files and run real commands on a
person's behalf, rather than just producing text in a chat window. Aider is
one example: it reads files, proposes edits, and (if configured to) applies
them and runs shell commands without further confirmation.

**Tool call**: a structured request a language model can emit asking the
surrounding program to do something specific, like "write this content to
this file." Ollama's API supports this as a `tool_calls` field in its
response. Whether a model *emits* a tool call and whether the surrounding
program *acts on it* are two different things, which is the whole point of
this project (see below).

**Canary string**: a unique, made-up marker string planted as part of an
injected instruction, asking the model to repeat it back if it read the
instruction. Checking for a canary string is a simple, mechanical way to
tell whether a reply was influenced by an injection, without a human
reading every reply or asking another model to judge it.

## The measurement

For each planted injection, this project records two independent yes/no
facts:

- **reply_changed**: did the agent's reply text contain that case's canary
  string? Checked with a plain string search, not a model judging another
  model's output.
- **tool_fired**: did something actually happen on disk or in git as a
  result? Checked by looking at the scratch repository's real files and
  git history after the run, not by reading the model's traffic.

These two facts are reported as a 2x2 and never collapsed into one "success
rate." The two cells where they disagree are the interesting ones:

- **reply changed, tool did not fire**: the agent talked about following
  the injection (or repeated the injected text back) but no real action
  happened. This is the "all talk" case a screenshot of the chat window
  would make look alarming, but nothing occurred.
- **reply did not change, tool fired anyway**: the agent's own words gave
  no sign anything unusual happened, but a real file or git action occurred
  regardless. A person reading only the reply text would miss this
  entirely. This is the more dangerous cell, because it is invisible to
  anyone who only checks what the model said.

## Why tool_fired is not read from Ollama's tool_calls field

Aider does not drive its normal file-editing behavior through Ollama's
`tool_calls` API field. Per Aider's own documentation, it asks the model to
write SEARCH/REPLACE blocks (or a full rewritten file) as plain text in its
reply, then Aider's own code parses that text and applies the edit to disk.
Shell commands work the same way: Aider looks for a specific text
convention in the reply, not a structured tool-call object.

This means a network proxy sitting between Aider and Ollama can only ever
see what the *model* asked for, never what the *agent* actually did with
it. If this project had scored `tool_fired` from the `tool_calls` field
alone, every single case would have shown zero, and that zero would have
looked like a finding ("the model never tries anything") when it would
actually have been a wrong measurement of an event that happens inside
Aider's own process, invisible to the network.

Instead, `tool_fired` in this project is read from the real, observable
side effect: a file's content on disk, a path that no longer exists, a
line that got added, a new git commit. The `tool_calls` field is still
recorded (see below) because it is an interesting secondary signal, just
not the one this project reports as the headline number.

## What gets recorded, and why two layers

Aider is pointed at a small FastAPI proxy (`src/agentic_injection/proxy.py`)
instead of talking to Ollama directly. The proxy forwards every request to
the real Ollama server unchanged and returns the response unchanged, so
Aider never notices it is there. On the way through, it writes a copy of
every `/api/chat` request and response to a SQLite database
(`evidence/proxy.db`). This is the LLM-layer record: what the model said
and whether it asked for a structured tool call.

Separately, `scripts/04_run_case.py` inspects the scratch repository's git
history and file contents before and after each run. This is the
side-effect record: what actually happened.

The two are joined by a sequence number in the SQLite table (an
autoincrement row id), read before and after each Aider invocation, since
Aider's own HTTP client does not forward a custom request-id header through
to Ollama that this project could otherwise use to join the two records.
Runs happen one at a time against one proxy process, so this join is exact.

## Corpus: where the injected instructions come from

The injected instructions are not invented for this project. They are
carried over from [InjecAgent](https://github.com/uiuc-kang-lab/InjecAgent)
(Zhan et al., ACL Findings 2024, arXiv:2403.02691), an MIT-licensed
benchmark of 1,054 indirect prompt injection test cases against
tool-using agents. Its own carrier is a poisoned tool-output field (for
example, a fake product review containing the injected instruction); this
project's contribution is re-carrying eight of its instructions into
software-development content a coding agent reads incidentally: a README,
a code comment, a docstring, a test fixture, and a commit message.

InjecAgent's own target actions are things like a smart-lock API, a bank
API, or a GitHub API. A local coding agent operating on a local repository
cannot call any of those APIs. Every case in `evidence/cases.json` records
exactly what was substituted (its `adapted` field) and cites which
InjecAgent test case it came from (`source_file` and `source_index`,
checked against the fetched corpus file by the test suite). Where a
target action transfers almost directly (deleting something, moving files
with a shell command), the substitution is small. Where InjecAgent's
target was a hosted API a coding agent has no equivalent for (sending an
email, calling a smart lock), the substitution re-aims the same
*intent* (exfiltrate something private, grant unauthorized access, weaken
an allowlist) at the nearest local filesystem/git equivalent.

Run `scripts/01_fetch_corpus.py` to fetch the three source files this
project reads from
(`corpus_src/dh_base.json`, `corpus_src/ds_base.json`,
`corpus_src/tools.json`); see `corpus_src/PROVENANCE.txt` for exact file
mapping.

## The smoke test

Before trusting a low tool-fired count as a finding about injection
resistance, this project first checks that the model can call a tool at
all. `scripts/00_smoke_test.py` sends five plain, non-injection prompts
("write this text to this file, using the write_file tool") through the
same proxy and checks that Ollama's response contains a well-formed
`tool_calls` entry. The recorded result is at
`evidence/smoke/tool_calling_smoke_test.json`. All five prompts produced a
valid tool call. This matters because if the model could not reliably call
a tool at all, a zero in the real experiment would be a fact about the
model's capability, not about its resistance to the injected instructions.
This check is a precondition for trusting the headline numbers, not the
finding itself.

## How to reproduce

Requires: the project's own `.venv` (Python 3.12, already set up with
aider, fastapi, uvicorn, httpx, pytest), and Ollama running locally with
`qwen3:4b` pulled.

```bash
cd /home/kali/director/projects/agentic-injection

# 1. Fetch the InjecAgent corpus files (idempotent, skips if already present)
.venv/bin/python3 scripts/01_fetch_corpus.py

# 2. Build the case manifest (traceable to the corpus, with adaptation notes)
.venv/bin/python3 scripts/02_build_cases.py

# 3. Start the recording proxy in its own terminal (or background it)
scripts/run_proxy.sh &

# 4. Run the tool-calling smoke test (validity precondition)
.venv/bin/python3 scripts/00_smoke_test.py

# 5. Run every case (rebuilds the scratch repo fresh before each one)
.venv/bin/python3 scripts/04_run_case.py

# 6. Aggregate into the 2x2
.venv/bin/python3 scripts/05_report.py

# 7. Run the test suite
.venv/bin/pytest
```

Every step is idempotent: re-running a script overwrites its own output
with a fresh result rather than appending to stale state. `04_run_case.py`
accepts `--case-id <id>` to run a single case.

## The sandbox

The agent only ever operates inside `scratch_repo/`, a git repository
created fresh by `scripts/03_build_scratch_repo.py` under this project's
own directory. It is rebuilt from scratch before every case (wiped and
recreated), so injected content from one case never carries into the next.
`scratch_repo/` is excluded from this project's own git history
(`.gitignore`). Nothing outside this project's directory was written to or
read by the agent during this build; see the report for an explicit
confirmation.

## Project layout

```
scripts/                   numbered, idempotent pipeline scripts
src/agentic_injection/     proxy.py (recording proxy), score.py (2x2 scorer)
corpus_src/                fetched InjecAgent source files + provenance note
scratch_repo/              the sandboxed repo the agent operates on (gitignored, rebuilt per case)
evidence/
  cases.json               the case manifest (source, adaptation, canary, check)
  generated_cases/         per-case injected text + copy of the source InjecAgent case
  smoke/                   the tool-calling smoke test result
  runs/                    one JSON per case: full aider transcript, reply text, git log, score
  proxy.db                 every /api/chat request/response the proxy saw
  summary.json             the aggregated 2x2
tests/                     pytest suite
FINDINGS.md                the actual numbers, traced to the files above
```

## What this project is not claiming

The general idea that a model's words and a model's actions can diverge is
already published. "Mind the GAP" (arXiv:2602.16943) measures exactly this
kind of divergence in frontier hosted models given direct harmful requests
in regulated domains like finance and healthcare. This project applies the
same kind of measurement to a different situation that paper did not
cover: an *indirect* injection planted in ordinary source-file content, a
*small local* model instead of a frontier one, and a *real coding agent's*
file and git actions instead of a synthetic domain benchmark. See
`FINDINGS.md` for the full novelty statement.

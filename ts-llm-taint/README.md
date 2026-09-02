# A taint analyzer for LangChain.js and Vercel AI SDK applications

This is a from-scratch static analyzer, written in TypeScript, that traces whether
untrusted data (a user's chat message, a document a retriever pulled back, a tool's raw
output) can reach a place where an LLM application treats it as trusted: a system
prompt, a message sent to the model, or a tool description the model reads as part of
its own instructions.

**Read this before anything else in this project: a materially better tool for part of
this problem already exists.** CodeQL, GitHub's commercial static analysis engine,
ships a query called `js/system-prompt-injection` (added in CodeQL 2.26.0, released
2026-07-08) that already does real, whole-program, cross-file taint tracking for
LangChain.js, explicitly modeling `SystemMessage`, `HumanMessage`,
`ChatModel.invoke/stream/call/predict/batch/generate`, `AgentExecutor`, `createAgent`,
and `ChatPromptTemplate.fromMessages` as sinks. That is a stronger engine than anything
built here, because CodeQL's dataflow library was built specifically to cross function
and file boundaries, which this analyzer largely cannot do (see "Scope" below). What
CodeQL does **not** have, verified by enumerating all 22 files in its own
`javascript/ql/lib/ext/` model directory on 2026-08-31, is any modeling at all for the
Vercel AI SDK (the `ai` npm package): no `ai-sdk.model.yml`, no `vercel*.model.yml`,
nothing. That gap, and evidencing real TypeScript/compiler-API competence, is what this
project exists to do. It is not a claim to be the first or the best taint analyzer for
LLM JavaScript applications.

## What is static analysis, and what is taint analysis

Static analysis means reading source code and reasoning about its structure without
running the program. Nothing executes, no model is called; a tool parses the code into
an **AST** (abstract syntax tree: the tree-shaped, structured representation of the
code that a parser produces, as opposed to the flat text a human reads) and then asks
questions about that structure.

Taint analysis is a specific, more useful kind of static analysis. Instead of asking
"does this one line look dangerous," it asks "can a value that started somewhere
untrusted reach somewhere dangerous, and by what path." Three things are named:

- a **source**: where untrusted data enters the program (an HTTP request field, a chat
  message's content, text a retriever fetched)
- a **sink**: a place where it is dangerous for that data to arrive unexamined (a
  system prompt, a shell command, a SQL query, a file path)
- a **sanitizer** (optional): a place along the way where the value is checked or
  cleaned, after which it is no longer treated as tainted

The analyzer traces whether a value can travel from a source to a sink without passing
through a sanitizer. That is a much better signal for injection-shaped bugs than
flagging every occurrence of a risky-looking function call, because the actual risk is
almost always the combination: untrusted input reaching a sensitive spot with nothing
in between to stop it.

## Why this matters for LLM applications specifically

An LLM reads its entire context (system prompt, user message, retrieved documents,
tool results) as one undifferentiated stream of text. It has no built-in way to tell
"an instruction I should follow" apart from "reference data I should just read." If a
retrieved document or a tool's output contains something that reads like an
instruction, the model can follow it. This is prompt injection, the top entry on the
OWASP LLM Top 10. Tracing whether untrusted text can reach the code that builds a
prompt or a tool description, without being separated or sanitized first, is exactly a
dataflow question, which is why taint analysis is a good fit for finding this class of
bug in code, not in the model's behavior at runtime (see "What this is not" below).

## What this project actually contains

- `src/`: the analyzer itself. `sources.ts` and `sinks.ts` each hold a table of typed
  rules that recognize one syntactic shape (an HTTP request property, a
  `SystemMessage` constructor argument, and so on). `propagation.ts` is the actual
  dataflow engine: it walks the AST tracking which values become tainted through
  assignment, template literals, object properties, and a single level of
  statically-resolvable function calls. `analyzer.ts` wires sources, propagation, and
  sinks together into a `Finding[]`. `cli.ts` is the command-line entry point.
- `fixtures/`: 11 planted-flaw files (one per source→sink pair, each with a header
  comment stating the expected result), 19 clean/negative files (sanitized versions,
  hardcoded-literal near-misses, and adversarial "looks similar but isn't" cases), and
  the two-file paired limit experiment described below.
- `corpus/` (gitignored, not vendored into this repo, see "Running it"): three real,
  permissively licensed LLM applications the analyzer is run against, with every hit
  hand-verified by reading the actual source.
- `tests/`: a vitest suite, 70 tests across four files, covering every source rule,
  every sink rule, the propagation engine's individual mechanics (assignment, template
  literals, the sanitizer-reassignment idiom, direct-call resolution, object property
  tainting), and the full analyzer pipeline run against every fixture.
- `logs/`: real captured output for every run referenced in `FINDINGS.md`.
- `FINDINGS.md`: the paired limit experiment's raw output, the real-code corpus results
  with every finding hand-verified, prior art, and an honest account of what this
  analyzer cannot catch.

## The engine: ts-morph, not the raw TypeScript compiler API

The analyzer is built on **ts-morph** (MIT, npm `28.0.0`), a wrapper around the
TypeScript compiler API. ts-morph does not replace or hide the compiler API; it wraps
it to make AST traversal and type-checking ergonomic (`getDescendantsOfKind`,
`findReferences`, `.getType()`) while still exposing the underlying compiler objects
(`.compilerNode`) when something isn't covered by the wrapper. Neither ts-morph nor the
raw compiler API gives you a control-flow graph or a dataflow graph for free: both
only expose the syntax tree and a type checker. All of the actual taint-propagation
logic in `propagation.ts` (following a path from source to sink) was written for this
project; no library did that part.

## Scope: what this analyzer can and cannot do

Stated up front, as a decision, not discovered by a reader later.

**What it does trace:**

- Direct assignment (`const b = a;`).
- Template literals (`` `...${tainted}...` ``) and `+` string concatenation.
- Object property assignment and object-literal construction (`obj.field = tainted`,
  `{ field: tainted }`), tracked per qualified property name so an unrelated property
  on the same object is not falsely tainted.
- A direct function call where the callee resolves to exactly one statically known
  function or arrow declaration (no overloads, no dynamic dispatch), with taint
  carried from argument to parameter and back out through the callee's `return`.
- A sanitizer, recognized only when it **reassigns** the tainted variable
  (`x = sanitize(x)`), the same idiom the sibling Semgrep project
  (`projects/semgrep-llm-rules`) required and documented as a known fragility.

**What it does NOT trace, named plainly:**

- **Callback/higher-order indirection**: a callback registered into a data structure
  and invoked later by unrelated code via a runtime lookup. This is the proven
  boundary, see "The paired limit experiment" below.
- **Cross-module and cross-file flow** beyond ordinary local type resolution. If a
  function is imported from another package (as in `convertToModelMessages` from the
  `ai` package in the real-code corpus, see `FINDINGS.md`), its body isn't available to
  walk, so taint stops there.
- **Destructuring assignment** (`const { messages } = await req.json();`): only plain
  `const x = expr;` is tracked.
- **Dynamic property access** (`obj[computedKey]`) where the key isn't a string
  literal.
- **Async boundaries beyond a direct, syntactically local `await`**: taint reaching a
  sink via a shared mutable object modified by a separately-scheduled callback is not
  tracked.
- **Control-flow-sensitive sanitization**: a sanitizer applied in only one branch is
  treated the same as everywhere; there is no branch/loop-aware narrowing.
- **Runtime behavior of any kind.** A finding here means "untrusted data can
  structurally reach a sink," never "the model obeyed an injected instruction" or "an
  attack succeeded."

One sink mapping is explicitly flagged as unverified rather than asserted as fact:
`tool().description` as a sink for **LangChain.js** specifically is inferred by analogy
to OpenAI's already-modeled `tool().description` sink in CodeQL's own model files, not
independently confirmed present in CodeQL's `langchain.model.yml` as of 2026-08-31. The
same sink shape for the **Vercel AI SDK's** own `tool({ description })` is directly
confirmed against the SDK's own docs and is not in question.

## The paired limit experiment

The Semgrep project proved where that engine stops seeing by building two minimally
different target files and measuring the raw finding-count difference, rather than
asserting a limitation from documentation alone. This project does the same thing, at a
boundary genuinely new to this engine: **callback indirection**, not plain
cross-function calls (ts-morph *can* attempt direct call-argument-to-parameter
propagation, so reusing that boundary would prove nothing new).

- `fixtures/limit-experiment/direct-call.ts`: an HTTP request value is passed directly,
  as a call argument, to a function whose body constructs a `SystemMessage` from it.
  The callee is statically resolvable to a single function declaration.
- `fixtures/limit-experiment/callback-indirection.ts`: minimally different, using the
  same source and the same sink, but the callback containing the sink is registered into a
  module-level array and invoked later by unrelated code via a runtime array lookup by
  index. The callback's declaration site and its invocation site are syntactically
  disconnected; no static edge connects "value passed to `dispatch()`" to "value
  received as the callback's parameter," because that binding exists only once the
  program actually runs.

Full raw output and interpretation: `FINDINGS.md`.

## Running it

```
npm install
npm run typecheck   # tsc --noEmit, strict mode, src/ and tests/
npm test            # vitest, 70 tests
npm run build       # emits src/ to dist/
npx tsx src/cli.ts "fixtures/**/*.ts"
npx tsx src/cli.ts "fixtures/**/*.ts" --json
```

The real-code corpus (`corpus/`) is gitignored rather than vendored into this
repository, to avoid committing three other projects' full source trees. To reproduce
the corpus results in `FINDINGS.md`:

```
cd corpus
git clone --depth 1 https://github.com/langchain-ai/langchain-nextjs-template.git
git clone --depth 1 https://github.com/vercel/ai-chatbot.git
git clone --depth 1 https://github.com/vercel-labs/ai-sdk-preview-rag.git
cd ..
npx tsx src/cli.ts "corpus/langchain-nextjs-template/**/*.{ts,tsx}"
npx tsx src/cli.ts "corpus/ai-chatbot/**/*.{ts,tsx}"
npx tsx src/cli.ts "corpus/ai-sdk-preview-rag/**/*.{ts,tsx}"
```

All three repos are permissively licensed (MIT or Apache-2.0), verified by reading each
repo's own `LICENSE` file directly rather than trusting GitHub's automated
license-detection field (see `FINDINGS.md` for why that distinction mattered for two of
these repos).

## What this is not

This is not a claim that static analysis can tell you whether an LLM application is
safe to run, and it is not a claim to be the first or best taint analyzer for LLM
JavaScript applications. CodeQL already does more, for LangChain.js specifically, than
this analyzer does. What this project can accurately claim: an independent,
from-scratch AST-and-type-checker implementation that evidences real TypeScript
capability, a real coverage extension for the Vercel AI SDK surface CodeQL currently
leaves unmodeled, and a rigorously measured, named boundary (callback indirection) for
exactly this architecture, reported with the same raw-output-first, hand-verified
standard the sibling Semgrep project used for its own limitation.

# Findings

## Versions tested

Recorded live on 2026-08-31 (`logs/environment.txt`):

- Node `v22.23.2`, npm `10.9.8`
- `typescript@7.0.2` (pinned as a devDependency, not left to whatever `ts-morph`
  vendors internally)
- `ts-morph@28.0.0`
- `vitest@4.1.11`

## The paired limit experiment

The sibling Semgrep project (`projects/semgrep-llm-rules`) proved where its engine
stops seeing dataflow by building two minimally different target files and measuring
the raw finding-count difference, rather than asserting a limitation from
documentation alone. This project repeats that method against a boundary that is
genuinely new to a ts-morph-based engine.

**Why not reuse the cross-function boundary that broke Semgrep OSS.** A plain
call-argument-to-parameter propagation, where a value crosses one function-call
boundary, is exactly the capability Semgrep OSS lacks in its free tier. A ts-morph AST
and type-checker pass **can** attempt that walk (see `resolveCallTaint` in
`src/propagation.ts`), so reusing that same boundary here would demonstrate nothing new
about this engine. The proposed boundary instead is **callback indirection**: a
callback whose declaration site and invocation site are connected only by a runtime
lookup (an array index, a map key), not by any static call edge.

**Setup** (`fixtures/limit-experiment/`): two files, minimally different.

- `direct-call.ts`: an HTTP request value (`req.body`) is read inside `handleRequest`
  and passed directly, as a call argument, to `processAndSend`, a single, statically
  resolvable function whose body constructs `new SystemMessage(value)` from its
  parameter.
- `callback-indirection.ts`: the same source (`req.body`), the same eventual sink
  (`new SystemMessage(value)`), but the sink-containing callback is registered into a
  module-level `handlers` array by `registerHandler(...)`, and separately invoked by
  `dispatch(value)`, which looks up `handlers[0]` at runtime and calls it. No static
  edge connects "the value passed to `dispatch()`" to "the value the stored callback
  receives as its parameter" (that binding exists only once the program actually runs
  and `handlers[0]` happens to hold the pushed callback).

**Run** (`npx tsx src/cli.ts <file>`, unmodified, both files run separately against the
same analyzer):

```
--- direct-call.ts ---
fixtures/limit-experiment/direct-call.ts:17  [http-request-to-prompt-construction]
  source (line 22): HTTP request property `req.body`
  sink   (line 17): SystemMessage constructor argument
  tainted argument: value

Total findings: 1

--- callback-indirection.ts ---
No findings.
Total findings: 0
```

Full captured output: `logs/limit_experiment_direct_call.log`,
`logs/limit_experiment_callback_indirection.log`.

**Result**: the direct-call flow produced exactly 1 finding, matching the expected
result stated in the fixture's own header comment. The callback-indirection flow, with
the same source and the same sink and only the connection mechanism changed, produced
0 findings. This is a hard wall for this specific, hand-built ts-morph pass, not a
"sometimes" limitation: the analyzer's own AST walk (`sourceRules`/`sinkRules` in
`src/sources.ts`/`src/sinks.ts`, matched by `analyzeSourceFile` in `src/analyzer.ts`)
never constructs an edge between `dispatch(tainted)` and the callback body, because no
such edge exists anywhere in the syntax tree; it exists only in the runtime array
`handlers`. **This claim is scoped to this hand-built ts-morph pass, not to static
analysis in general.** A whole-program pointer analysis, which is what CodeQL's
dataflow library approximates, might catch or miss this specific case depending on how
its own callback modeling handles a runtime array lookup; that question was not tested
here and is not asserted either way.

## Fixture corpus results

11 planted-flaw files (one per source-to-sink pair), 19 clean/negative files, run
together:

```
npx tsx src/cli.ts "fixtures/**/*.ts"
```

Full captured output: `logs/all_fixtures_run.log`. **13 findings across 12 files**
(11 of the 12 planted files with a genuine forward-composable flow produce exactly 1
finding each; `human-message-into-fromMessages.ts` produces 2, both on the same real
bug, from two independent rule pairs, see below). **0 findings across all 19 clean
files** and 0 findings on `callback-indirection.ts`.

| source category | sink category | fixture | findings |
|---|---|---|---|
| http-request | prompt-construction | `http-request-to-system-message.ts` | 1 |
| http-request | prompt-construction | `human-message-into-fromMessages.ts` | 2 (see note) |
| user-message | prompt-construction | `user-message-to-chat-prompt-template.ts` | 1 |
| retrieved-document | prompt-construction | `retrieved-document-to-generate-text.ts` | 1 |
| retrieved-document | prompt-construction | `retrieved-document-to-system-message-in-tool.ts` | 1 |
| retrieved-document | prompt-construction (tool description) | `retrieved-document-to-tool-description.ts` | 1 |
| http-request | shell-execution | `http-request-to-shell-execution.ts` | 1 |
| http-request | code-execution | `http-request-to-eval.ts` | 1 |
| http-request | sql-query | `http-request-to-sql-query.ts` | 1 |
| http-request | file-path | `http-request-to-file-read.ts` | 1 |
| http-request | unsanitized-render | `http-request-to-dangerously-set-inner-html.ts` | 1 |
| http-request (direct-call case) | prompt-construction | `limit-experiment/direct-call.ts` | 1 |

**Note on `human-message-into-fromMessages.ts`'s 2 findings**: this is not
double-counting a false positive. A `HumanMessage`'s content is, by definition,
user-controlled, so the analyzer's `humanMessageConstructorRule` treats the
`HumanMessage` constructor's own argument as **both** a sink (an http-request value
reaching it) **and** a source (that same content is itself untrusted user-message
data, which is then independently checked against every sink, including the same
`HumanMessage` constructor it originated from). Both findings point at the same line
and the same real bug: two independent, correct rule pairs agreeing on one vulnerable
line, not two rules double-firing on the same match.

### A false positive found and fixed during construction

While building the fixture corpus, `clean/human-message-hardcoded.ts`
(`new HumanMessage("Hello, how can I help you today?")`, a fully hardcoded literal, no
external input anywhere) was flagged by an earlier version of
`humanMessageConstructorRule`. The rule treated any `HumanMessage` constructor
argument as a source, reasoning "a HumanMessage's content is definitionally
user-controlled," but that reasoning is wrong for a developer-written string literal:
no user ever supplied that specific value. The fix (`src/sources.ts`,
`humanMessageConstructorRule`, `userMessageObjectRule`, `toolMessageConstructorRule`)
excludes `StringLiteral` and `NoSubstitutionTemplateLiteral` arguments from all three
message-constructor source rules. This is reported here rather than fixed silently,
because it is exactly the class of false positive this project's own scoring method
exists to catch.

### Tool-result source category: a design limitation found while building fixtures

The `tool-result-return` source rule (`src/sources.ts`) recognizes a `return <expr>`
statement inside an AI SDK `tool()`'s `execute` callback as untrusted tool-produced
data. Its captured source node is the entire returned expression. This composes
correctly when the sink usage is inside that same expression (see
`fixtures/planted/retrieved-document-to-system-message-in-tool.ts`, which fires
correctly, sourced from a nested `retriever.similaritySearch()` call rather than the
`tool-result-return` rule itself), but no realistic, forward-composable fixture was
found where `tool-result-return`'s own captured node is what the analyzer reports as
the finding's source. The reason is structural: `propagation.ts`'s
`isExpressionTainted` recognizes a value as tainted starting only at the exact AST node
a source rule matched, with no backward propagation to earlier uses of the same
variable. A tool's `return` statement is, by construction, the last statement to run in
that function, so anything computed from it cannot be reused *forward* within the same
function body after the point of return. The rule is directly unit-tested
(`tests/sources.test.ts`) to confirm it matches the shape it is meant to match, and it
remains available in the source table for interprocedural engines with fuller
call-graph modeling (such as CodeQL), but this project does not claim a fixture
demonstrating it end to end as a finding's reported source, and states that here rather
than manufacturing an artificial fixture that misrepresents what the engine actually
traces.

## Real-code corpus results

Three real, permissively licensed LLM applications, license-verified by reading each
repository's own `LICENSE` file directly (not GitHub's automated license-detection
field, which reported `NOASSERTION` for two of the three, a documented SPDX-detection
artifact for monorepos, not an actual licensing ambiguity):

| Repository | License (verified by reading `LICENSE`) | Files scanned | Findings |
|---|---|---|---|
| `langchain-ai/langchain-nextjs-template` | MIT | 35 `.ts`/`.tsx` | 2 |
| `vercel/ai-chatbot` | Apache-2.0 | 153 `.ts`/`.tsx` | 0 |
| `vercel-labs/ai-sdk-preview-rag` | MIT | 17 `.ts`/`.tsx` | 0 |

Full captured output: `logs/corpus_langchain_nextjs_template.log`,
`logs/corpus_ai_chatbot.log`, `logs/corpus_ai_sdk_preview_rag.log`.

### `langchain-nextjs-template`: 2 findings, both hand-verified as genuine

```
app/api/chat/agents/route.ts:26  [user-message-to-prompt-construction]
  source (line 26): HumanMessage constructor argument `getMessageText(message)`
  sink   (line 26): HumanMessage constructor argument
  tainted argument: getMessageText(message)

app/api/chat/retrieval_agents/route.ts:28  [user-message-to-prompt-construction]
  source (line 28): HumanMessage constructor argument `getMessageText(message)`
  sink   (line 28): HumanMessage constructor argument
  tainted argument: getMessageText(message)
```

Both files were opened and read directly. In both, a helper
`getMessageText(message)` extracts the plain-text content of an incoming Vercel AI SDK
`UIMessage` (the chat request body), and that value is passed straight into
`new HumanMessage(getMessageText(message))` when converting the request's messages
into LangChain.js's own message format. This is a structurally accurate finding: a
`HumanMessage`'s content is, in this real application, literally the end user's raw
chat input, reaching LangChain's own message constructor with no intervening check.
It is not a bug in the ordinary sense (a chat app's user turn is supposed to carry the
user's text), but it is exactly the code shape the `user-message` source category is
built to surface, and it correctly demonstrates the analyzer finding a real,
verifiable flow in a real, unmodified, third-party codebase.

### `vercel/ai-chatbot`: 0 findings, and the interesting reason why

`ai-chatbot`'s own chat route (`app/(chat)/api/chat/route.ts`) calls `streamText` with
`messages: modelMessages`, where `modelMessages` is assigned on an earlier line as
`const modelMessages = await convertToModelMessages(uiMessages);`.
`convertToModelMessages` is imported from the `ai` package itself, not declared
locally in this file, so `resolveCallTaint`'s single-declaration resolution (see
`src/propagation.ts`) cannot walk into its body; the function's implementation lives
in a different package the analyzer never parses. This is not a coverage gap that was
missed by accident, it is the documented, named scope boundary
("cross-module and cross-file flow", `README.md`) operating exactly as designed on
real code, on the very first real file it was tested against with that shape. Note
also that this repository's `instructions` field in the same call
(`systemPrompt({ requestHints, supportsTools })`) is itself an unresolvable imported
function call, so it too is correctly not flagged, since there is no literal or
directly-composed tainted value at that argument position to trace in the first place.

### `vercel-labs/ai-sdk-preview-rag`: 0 findings, and a second, different reason

This repository's `app/(preview)/api/chat/route.ts` calls `streamText` with
`messages: convertToModelMessages(messages)`, where `messages` comes from
`const { messages }: { messages: UIMessage[] } = await req.json();`. This is a
**destructuring assignment**, a documented, out-of-scope propagation case
(`README.md` "Scope"): the analyzer's `propagateThroughStatements` only recognizes
plain `const x = expr;` declarations, not object-pattern destructuring, so `messages`
is never marked tainted at its declaration even though `req.json()` is a recognized
HTTP-request source shape (`httpRequestJsonCallRule`, `src/sources.ts`). This is a
second, independent, real example of a documented limitation firing correctly on
unmodified third-party code, not a repeat of the same gap.

### False-positive probes: 0 findings across two LLM-adjacent, non-vulnerable directories

Mirroring the Semgrep project's choice to scan its own harness's non-vulnerable code
as a false-positive check, this project scanned two directories that are LLM-adjacent
but structurally uninvolved in prompt construction:

1. `langchain-nextjs-template/components/` (14 `.tsx` files, the app's UI layer):
   **0 findings**. Full output: `logs/false_positive_probe_langchain_components.log`.
2. `ai-chatbot/lib/db/` (4 `.ts` files, the app's database layer): **0 findings**.
   Full output: `logs/false_positive_probe_ai_chatbot_db.log`.

Total false positives across both probes: **0**.

## Prior art, stated plainly

**CodeQL** (`github/codeql`) already ships `js/system-prompt-injection`
(CodeQL 2.26.0, released 2026-07-08), a real, interprocedural, path-sensitive taint
query built on CodeQL's mature `TaintTracking` dataflow library. It explicitly models
LangChain.js's `SystemMessage`, `HumanMessage`,
`ChatModel.invoke/stream/call/predict/batch/generate`, `AgentExecutor`,
`createAgent`, and `ChatPromptTemplate.fromMessages` as sinks, confirmed directly
against GitHub's own `javascript/ql/lib/ext/langchain.model.yml`. This is a stronger
engine than anything built here for LangChain.js specifically, because CodeQL's
dataflow library is built to cross function and file boundaries by construction,
which is exactly the wall this project's own paired limit experiment (and the
`vercel/ai-chatbot` real-code result above) demonstrates this analyzer does not
cross.

**What CodeQL does not have**, verified by direct enumeration of every file in
`github/codeql`'s `javascript/ql/lib/ext/` directory on 2026-08-31 (22 files:
anthropic, openai, google-genai, langchain, openrouter, aws-sdk, axios, react, vue,
and others): no `ai-sdk.model.yml`, no `vercel-ai.model.yml`, no file of any name
modeling the Vercel AI SDK's `generateText`/`streamText`/`tool()` surface. CodeQL's
shipped query, as of this fetch, does not flag any Vercel AI SDK call shape at all.
That is a real, verifiable gap this project's own source/sink tables cover
(`aiSdkGenerateCallRule`, `toolDescriptionRule` in `src/sinks.ts`).

**Semgrep** has no LangChain.js- or Vercel-AI-SDK-specific JS/TS taint rules found in
this project's own research (see `.research/incoming/typescript-llm-taint-analyzer.md`
for the search basis), and Semgrep OSS shares the same interprocedural ceiling
documented in the sibling `projects/semgrep-llm-rules` project, for a different
language and a different engine.

**No dedicated open-source "LLM app taint analyzer for TypeScript" project** was found
by name during this project's research beyond CodeQL's built-in query.

**Honest positioning**: this project does not claim to be the first or best static
analyzer for this problem. CodeQL substantially already solves the LangChain.js half
of it, with an engine this project's hand-built AST pass cannot match on
interprocedural reach. What this project adds is a real, from-scratch TypeScript and
compiler-API implementation (evidencing a skill this portfolio otherwise does not
demonstrate), a genuine, verified coverage extension for the Vercel AI SDK surface
CodeQL currently leaves unmodeled, and a rigorously measured, explicitly-scoped
boundary (callback indirection) reported with the same raw-output-first,
hand-verified standard the sibling Semgrep project used for its own OSS/Pro boundary
finding.

## What this analyzer cannot catch

Restated here with the same specificity as the positive results above, not as a
vague disclaimer:

- **Taint analysis sees code shape, not runtime behavior.** A finding means
  "untrusted data can structurally reach a sink," never "a prompt injection attempt
  succeeded" or "the model obeyed an injected instruction." Nothing here executes any
  model or any application code.
- **Callback indirection is an unconditional wall for this engine**, proven above, not
  assumed. Any code where a sink-containing function's invocation is decided at
  runtime by a lookup rather than a static call expression is invisible to this
  analyzer, full stop, for this architecture.
- **Cross-module resolution stops at the file/package boundary** whenever the callee
  is imported from a package this analyzer does not itself parse (demonstrated
  directly by the `vercel/ai-chatbot` real-code result above, not a synthetic
  example).
- **Destructuring assignment is not tracked at all** (demonstrated directly by the
  `ai-sdk-preview-rag` real-code result above).
- **Sanitizer recognition requires reassignment**, the same fragility the sibling
  Semgrep project documented: `if (!authorize(x)) return;` without reassigning `x`
  does not clear taint on `x`, verified directly in
  `tests/propagation.test.ts`'s "does NOT clear taint from a bare gating call" test.
- **No control-flow sensitivity.** A sanitizer applied in only one branch of an
  `if`/`else` is treated as if it applied everywhere; this analyzer's
  `propagateThroughStatements` walks both branches of an `if` unconditionally.
- **No points-to/alias analysis.** A shared mutable object modified by a separately
  scheduled callback, or taint carried through a `Promise` chain that isn't a direct,
  syntactically local `await`, is not tracked.
- **One sink mapping is explicitly unverified**: `tool().description` as a sink for
  LangChain.js specifically (as opposed to the Vercel AI SDK's own `tool()`, which is
  directly confirmed) is inferred by analogy to OpenAI's already-modeled
  `tool().description` sink in CodeQL's own model files, not independently confirmed
  present in CodeQL's `langchain.model.yml` as of 2026-08-31. The analyzer's own output
  labels this finding category as unverified (see `src/sinks.ts`, `toolDescriptionRule`)
  rather than presenting it with the same confidence as the confirmed sinks.

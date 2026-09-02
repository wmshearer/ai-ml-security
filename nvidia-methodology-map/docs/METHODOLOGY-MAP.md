# Mapping this portfolio against NVIDIA's published AI Red Team methodology

Prepared for interview positioning. Sources are the four posts assigned plus the
`ai-red-team` tag page on the NVIDIA Developer blog, checked directly (not from search
snippets). Quotes are marked as quotes; everything else is paraphrase, marked as such.

## What NVIDIA published

NVIDIA's AI Red Team (AIRT) does not publish one single canonical "methodology
document." What exists is a set of blog posts spanning 2023 to 2026 that together sketch
a framework, but the framework itself is thin and mostly appears once, in the 2023
introduction post. Later posts are closer to individual technical case studies and
position pieces than restatements of a formal process. Below, posts are grouped by what
they actually contain.

### The one post with a formal framework: "NVIDIA AI Red Team: An Introduction" (June 14, 2023, Will Pearce and Joseph Lucas)

This is the only post that lays out a structured assessment framework. It organizes the
program around two "core building blocks": **Governance, Risk, and Compliance (GRC)**
and **ML Development**, and frames risk into three categories:

- **Technical risk** - "ML systems or processes are compromised as the result of a
  technical vulnerability or shortcoming" (paraphrase of their category description).
- **Reputational risk** - model performance reflects poorly on the organization or has
  broad societal impact (paraphrase).
- **Compliance risk** - non-compliance leading to fines or reduced competitiveness
  (paraphrase).

The post's Table 2 lays out assessment phases, in this order (paraphrase of the table,
not a direct quote of a numbered list in body text):

1. **Reconnaissance** - described as using "classic reconnaissance techniques found in
   MITRE ATT&CK or MITRE ATLAS."
2. **Technical vulnerabilities** - traditional application security vulnerabilities.
3. **Model vulnerabilities** - extraction, evasion, inversion, membership inference,
   poisoning.
4. **Harm and abuse** - model misuse, bias, environmental misalignment.

A separate table (Table 1) maps this against the ML development lifecycle: Ideation to
Data Collection to Data Processing to Model Training to Model Evaluation to Model
Deployment to System Monitoring to End-of-Life.

Named techniques in this post: prompt injection assessment, privilege tiering between
infrastructure layers, security controls on model file formats (blocking pickle files
outside development, requiring ONNX in production), tabletop exercises for scenario
analysis.

On communication: the post says the intent is that "all efforts live within a single
framework that stakeholders can reference" (close paraphrase) for a shared view of ML
security risk and assessment scope. This is the only post with an explicit statement
about how findings/scope get communicated across the org, as opposed to how a single
finding is written up.

### "AI Red Team: Machine Learning Security Training" (October 19, 2023, Will Pearce, Joseph Lucas, Rich Harang, John Irwin)

Describes a two-day internal/external training course, not an assessment methodology.
It explicitly refers back to the 2023 introduction post rather than restating a
process: "Students were given a basic methodology based on our own framework"
(quote), citing the introduction post as the source. The course itself covered
Evasion, Extraction, Assessments, Inversion, Membership Inference, Poisoning, and LLM
applications, using "over 20 Jupyter notebooks and 200 slides" (quote-adjacent, close
paraphrase of the figures given). This post is evidence the framework from the 2023
post is treated internally as the reference document, but adds no new structure of its
own.

### "Defining LLM Red Teaming" (February 25, 2025, Leon Derczynski, Rich Harang, Sadaf Khan)

This is the most conceptually dense post and the closest thing to a second framework,
but it is a taxonomy of what red teaming *is*, not a step-by-step assessment process.
It gives five defining characteristics of LLM red teaming, presented as direct claims
about the practice:

1. "It's limit-seeking" - red teamers find boundaries and explore limits in system
   behavior.
2. "It's never malicious" - people doing red teaming are not interested in doing harm.
3. "It's manual" - "the parts of red teaming that can be automated are often most
   useful to give human red teamers insight," implying automation supports but does not
   replace the human practice.
4. "It's a team effort" - practitioners build on each other's techniques and prompts.
5. It's approached with an "alchemist mindset" - red teamers abandon rationalizations
   about models (paraphrase of the framing).

It also gives five strategy categories for how attacks are actually carried out:
**Language** (surface-form manipulation, e.g. encoding), **Rhetorical** (argumentation
or manipulation), **Possible worlds** (shifting interaction context), **Fictionalizing**
(shifting to a fictional frame), and **Stratagems** (meta-strategies about how one
interacts with the model).

Scope statement, and this is the load-bearing one for positioning any of this
portfolio's work: the post splits red teaming into **security red teaming**, scoped to
"the technology stack leading up to the point of inference output," and **content red
teaming**, scoped to "the content produced at model inference time." This is NVIDIA's
own explicit division between what happens before/around inference (application,
plumbing, tool use) and what the model says at inference time.

On documentation: the post states findings get folded into "Model Card++"
documentation, and that the team practices "coordinated vulnerability disclosure,"
giving model owners time to respond before public release of an exploit (paraphrase of
the disclosure-timing claim).

Tools named: NVIDIA garak ("Generative AI Red-Teaming and Assessment Kit") and NVIDIA
NeMo Guardrails.

### "Practical LLM Security Advice from the NVIDIA AI Red Team" (October 2, 2025, Rich Harang, Joseph Lucas, John Irwin, Becca Lynch, Leon Derczynski, Erick Galinkin, Daniel Teixeira, Kai Greshake)

Eight authors, the largest byline of any post reviewed. Not a methodology post; it is a
"common findings" writeup drawn from repeated assessments. Framing quote: "Over the
last several years, the NVIDIA AI Red Team (AIRT) has evaluated numerous and diverse
AI-enabled systems for potential vulnerabilities and security weaknesses before they
reach production" (quote). It groups recurring issues into three buckets, presented as
patterns seen across engagements rather than a scoring rubric: code execution
(`exec`/`eval` on LLM-generated code) leading toward RCE, insecure RAG access controls,
and active-content rendering exploits (malicious links/images/markdown rendered back to
a user). No explicit in-scope/out-of-scope statement is made; it reads as "these are
the things we keep finding," not "here is our checklist."

### Posts on the tag page not in the original four-post list

The `developer.nvidia.com/blog/tag/ai-red-team/` tag page lists sixteen posts, twelve
of which were not in the assigned list. In order of relevance to methodology, the
ones read in full:

- **"Modeling Attacks on AI-Powered Apps with the AI Kill Chain Framework"**
  (September 11, 2025, Rich Harang). This is the second real framework in the corpus,
  and arguably more load-bearing for attack-path work than the 2023 introduction post.
  It defines a five-stage kill chain: **Recon** (mapping data ingestion routes,
  exploitable tools, guardrail locations, memory types), **Poison** (placing malicious
  input via direct or indirect prompt injection), **Hijack** (malicious input triggers
  attacker-serving output via tool use, exfiltration, or misinformation), **Persist**
  (embedding payloads in session history, cross-session memory, or agentic plans so
  influence survives), and **Iterate/Pivot** (in agentic systems, exploiting feedback
  loops to move laterally, rewrite agent goals, or establish command-and-control), with
  an **Impact** stage where hijacked output triggers real-world action. Governing
  principle, quoted: "Assume prompt injection." Scope statement: the framework is about
  "attacks against AI systems themselves," explicitly distinguished from AI used as a
  weapon for other attacks.

- **"Agentic Autonomy Levels and Security"** (February 25, 2025, Rich Harang and Martin
  Sablotny). Defines four autonomy levels for agentic systems: **Level 0 - Inference
  API** ("a single user request results in a single inference call to a single
  model," quote), **Level 1 - Deterministic System** (multiple inference calls in a
  predetermined order not dependent on input or results), **Level 2 - Weakly Autonomous
  System** (the model can decide whether/how to call plugins at fixed decision points),
  and **Level 3 - Fully Autonomous System** (the model can freely decide if, when, or
  how to call plugins or revise its own plan). Key scope claim: "The risk associated
  with these systems lies mostly in the tools or plugins available to those systems"
  (close paraphrase). Names taint tracing as a mitigation: "marking an execution flow as
  having received untrusted data and then either preventing use of or requiring manual
  re-authorization for sensitive tool[s]" (quote-adjacent).

- **"How Code Execution Drives Key Risks in Agentic AI Systems"** (November 3, 2025,
  John Irwin and Kai Greshake). A case study built around CVE-2024-12366 in the
  PandasAI library, walked as a five-step attack chain: guardrail evasion, input
  preprocessing targeting output variables, code generation producing malicious
  instructions, payload escaping execution constraints, and terminal command delivery.
  Explicitly generalizes past the single case: "While this example was identified
  during an evaluation of an analytics workflow, the core issue isn't specific to a
  single integration or library" (quote). States a position that sanitization alone is
  insufficient and structural sandboxing is required, and documents a disclosure
  timeline from initial finding through coordination with CERT/CC.

- **"Why CVEs Belong in Frameworks and Apps, Not AI Models"** (September 26, 2025, Rich
  Harang, Joseph Lucas, Erick Galinkin). Not a technique post, a scoping position. Its
  core claim: "Vulnerabilities live in the surrounding code, such as session
  management, data handling, or framework serialization, not in the static weight
  files" (quote). It sets an explicit two-part test for whether something warrants a
  CVE: "(1) Has the model failed its intended inference function in a way that violates
  a security property? (2) Is the issue unique to this model instance such that a CVE
  ID would help users identify and remediate it?" (quote). Under this test, model
  extraction, data leakage, adversarial inputs, and unsafe deserialization during
  loading are ruled out as application-layer problems, because in each case "the model
  is behaving as expected" (paraphrase of the framing). The one exception they name:
  "deliberately training data poisoning that implants reproducible backdoors in
  specific weight files" (quote), though they still favor supply-chain assurance over a
  CVE for that case.

- **"Sandboxing Agentic AI Workflows with WebAssembly"** (December 16, 2024, Joseph
  Lucas). A specific mitigation proposal: move LLM-generated Python execution out of
  the application server and into the user's browser via Pyodide (a CPython-to-Wasm
  port) with micropip for package installs. Regex-based filtering and restricted Python
  runtimes are explicitly dismissed as insufficient. Does not reference garak, does not
  describe a testing/measurement methodology; it is an architecture proposal, not an
  assessment post.

- **"Securing Agentic AI: How Semantic Prompt Injections Bypass AI Guardrails"** (July
  31, 2025, Daniel Teixeira) and **"How Hackers Exploit AI's Problem-Solving
  Instincts"** (August 7, 2025, Daniel Teixeira). Both are technique demonstrations
  (multimodal/rebus-style visual prompt injection against early-fusion models;
  "cognitive attacks" embedding instructions inside puzzles a reasoning model has to
  solve, tested against Gemini 2.5 Pro). Neither names garak or NeMo Guardrails.
  Neither states a formal in/out of scope boundary. The second post is explicit that
  its own findings are limited: "specific findings presented here are based on
  controlled testing environments and should be considered proof-of-concept rather than
  comprehensive security analysis" (quote).

- Not read in full for this report (lower relevance to methodology; noted for
  completeness from the tag page): "Four Ways to Deploy More Secure AI Agents" (Jul 30,
  2026), "Improving Bash Generation in Small Language Models with Grammar-Constrained
  Decoding" (May 8, 2026), "Mitigating Indirect AGENTS.md Injection Attacks in Agentic
  Environments" (Apr 20, 2026), "Practical Security Guidance for Sandboxing Agentic
  Workflows and Managing Execution Risk" (Jan 30, 2026), "Updating Classifier Evasion
  for Vision Language Models" (Jan 28, 2026), "From Assistant to Adversary: Exploiting
  Agentic AI Developer Tools" (Oct 9, 2025), "Structuring Applications to Secure the KV
  Cache" (Apr 29, 2025). These appear to be further individual technique/case-study
  posts in the same pattern as the ones above, not additional methodology statements.
  If any of these turn out to matter for a specific conversation, they should be read
  before relying on them.

### So: is there a formal methodology?

Partially, and it is fragmented across posts rather than restated as one document.
There are two real named frameworks: the 2023 introduction post's four-phase assessment
structure (Recon, Technical vulnerabilities, Model vulnerabilities, Harm and abuse) tied
to the ML development lifecycle, and the 2025 AI Kill Chain (Recon, Poison, Hijack,
Persist, Iterate/Pivot, Impact). They are not presented as the same framework, or as one
superseding the other; the 2023 one is an assessment-program structure, the 2025 one is
an attack-path/kill-chain model for reasoning about a specific attack. The "Defining LLM
Red Teaming" post adds a taxonomy of red-teaming characteristics and a strategy
categorization, which is descriptive of practice rather than a checklist to run. Most
of the rest of the corpus is discursive: individual case studies, position statements
on scope (the CVE post), and demonstrations of technique, presented as "here is what we
found" rather than "here is our numbered process." Anyone citing "NVIDIA's methodology"
in an interview should be specific about which of these two frameworks, or the taxonomy,
they mean, since the posts do not treat them as interchangeable.

## Where this portfolio already matches

| NVIDIA's stated practice (quote or close paraphrase) | Portfolio project | What specifically demonstrates it |
|---|---|---|
| Kill Chain "Poison" stage: attacker places malicious input via "indirect prompt injection" through "data sources like RAG databases" (paraphrase of the Kill Chain post's Poison stage) | `rag-poisoning` | Four-stage measurement (retrieved, contaminated, aligned, actioned) of exactly this attack path, with a real retrieval-scoring mechanism and quantified rates (0% to 70% retrieval depending on padding, 20% end-to-end action) rather than a pass/fail claim. This is a direct, instrumented study of the specific stage NVIDIA names, not an adjacent topic. |
| "Defining LLM Red Teaming" scope split: "security red teaming" targets "the technology stack leading up to the point of inference output" versus "content red teaming" scoped to "the content produced at model inference time" (quotes) | `garak-tool-observability` | The project's entire finding is that garak, built to check the model's inference-time output, cannot observe the technology-stack side (whether a tool call actually fired). It demonstrates, with a live agent and a concrete count (38 of 106 runs where an unauthorized tool call was scored as "passed"), the exact boundary NVIDIA's own scope split describes, from the side NVIDIA's split does not instrument. |
| Agentic Autonomy Levels post: "The risk associated with these systems lies mostly in the tools or plugins available to those systems," and taint tracing as a named mitigation, "marking an execution flow as having received untrusted data and then either preventing use of or requiring manual re-authorization for sensitive tool[s]" (quotes) | `ai-redteam-harness` and `semgrep-llm-rules` | `ai-redteam-harness` builds a Level 2-ish agent (tool calls at model discretion: `lookup_employee`, `send_email`, `read_file`) and demonstrates excessive-agency tool misuse against it with captured output. `semgrep-llm-rules` implements the taint model NVIDIA names directly: source (untrusted retrieved/tool text), sink (prompt construction or a dangerous action), sanitizer, and traces whether tainted data reaches a sink unchecked, which is the identical source-sink-sanitizer shape NVIDIA describes for tool re-authorization. |
| 2023 introduction post: model-format controls, "blocking pickles outside development" and preferring safer formats in production (paraphrase); AI Kill Chain "Recon" stage includes mapping "exploitable tools, open source libraries" (paraphrase) | `ai-supply-chain-audit` | Measures exactly the pickle-format exposure NVIDIA's 2023 controls guidance addresses, at ecosystem scale (28 of 50 top Hugging Face models ship at least one pickle-format weight), and separately tracks OSV advisories per package in the stack, which corresponds to the "open source libraries" recon target named in the Kill Chain. |
| "Why CVEs Belong in Frameworks and Apps, Not AI Models": "Vulnerabilities live in the surrounding code... not in the static weight files" (quote), and the model-behaving-as-expected framing for what does not count as a defect | `ai-supply-chain-audit`'s explicit "what this measures, and what it refuses to" section | The project's own scope discipline (measuring exposure, not malice; treating a pickle-format file as not itself malicious) lines up with NVIDIA's argument that the weight file/format is not where the vulnerability is, the surrounding handling is. Both projects draw the same line between "file format risk" and "actual malicious payload," independently. |

## Where it does not match

- **No coordinated disclosure practice demonstrated.** NVIDIA's "Defining LLM Red
  Teaming" post states the team practices "coordinated vulnerability disclosure," and
  the code-execution post documents an actual CERT/CC-coordinated disclosure timeline.
  Nothing in this portfolio runs a disclosure process; the closest artifact is the
  unposted draft comment for garak's public issue #1969 in `garak-tool-observability`,
  which is a community contribution gesture, not a disclosure process against a
  production system.

- **No GRC/organizational framing.** The 2023 introduction post frames the whole
  program around Governance, Risk, and Compliance plus the ML development lifecycle
  (Ideation through End-of-Life), with technical/reputational/compliance risk
  categories. This portfolio's AI-security work is entirely technical measurement; there
  is no artifact that frames findings against organizational risk categories or ties
  them to lifecycle stage the way NVIDIA's framework does. (`redteam-program-charter`
  does this kind of program framing, but for a generic red team program against a
  fictional org, not for AI-specific risk categories, and it is not itself an AI
  security project.)

- **No membership inference, model inversion, or extraction work.** NVIDIA's 2023 model
  vulnerability category names extraction, evasion, inversion, membership inference, and
  poisoning as the core ML-specific attack classes, and the training post spends modules
  on each. This portfolio has poisoning (`rag-poisoning`) and prompt-injection/evasion-
  adjacent work (`ai-redteam-harness`), but nothing that measures model extraction,
  inversion, or membership inference against a target model.

- **No multimodal or vision-language attack work.** Two 2025 posts (semantic/rebus
  prompt injection, puzzle-embedded "cognitive attacks" against Gemini 2.5 Pro) and one
  2026 post title ("Updating Classifier Evasion for Vision Language Models," not read in
  full) show NVIDIA actively working multimodal attack surfaces. Nothing in this
  portfolio touches image or multimodal input; everything here is text-only.

- **No kill-chain "Persist" or "Iterate/Pivot" stage work.** The AI Kill Chain names
  persistence across sessions (embedding payloads in cross-session memory, shared
  resources, agentic plans) and lateral pivot/command-and-control as later stages.
  Nothing in this portfolio tests multi-session memory persistence or agent-to-agent
  pivoting; `ai-redteam-harness` and `rag-poisoning` are both single-session,
  single-turn measurements.

- **No sandboxing/architecture-mitigation build.** NVIDIA has two full posts (WebAssembly
  sandboxing, and general sandboxing guidance referenced on the tag page) proposing and
  building specific architectural mitigations for code-execution risk. This portfolio's
  closest artifact, `gguf-fuzzing`, tests a parser for crash/hang bugs, which is
  adjacent (both are about untrusted input reaching code) but is not a mitigation-
  architecture project; nothing here builds or evaluates a sandbox.

- **`security-analysis-agent` is unfinished** and, as of this review, contains only a
  `build_ground_truth.py` script with no README, no eval results, and empty `data/`,
  `eval/`, and `traces/` directories. It cannot presently be used as evidence of anything
  and should not be cited in an interview until it has content.

## Points of genuine tension or disagreement

- **The CVE-scoping post and `ai-supply-chain-audit` are aligned in argument but this
  should be stated carefully.** NVIDIA's CVE post argues vulnerabilities belong in
  "the surrounding code," not model weights, and that most proposed model CVEs describe
  normal statistical behavior or application flaws. `ai-supply-chain-audit` independently
  lands on a similar distinction (exposure versus malice, format versus payload) but for
  a different question (pickle-format prevalence, not CVE eligibility). These are
  compatible positions, not the same claim, and should not be presented as if the
  portfolio project "confirms" NVIDIA's CVE argument; it addresses an adjacent, narrower
  question.

- **The garak tool-observability gap is the clearest substantive tension, and it is
  worth naming precisely rather than softening it.** See the dedicated section below.

- **No direct evidence found that NVIDIA's own posts discuss agent tool-call
  observability as a gap in garak specifically.** The posts describe garak as scoped to
  inference-time output ("content produced at model inference time," from "Defining LLM
  Red Teaming"), and the Kill Chain and Autonomy Levels posts both clearly treat tool
  invocation as a first-class risk surface. But none of the four assigned posts, nor the
  additional ones read, states in NVIDIA's own words that garak has a known gap around
  scoring tool actions rather than text. That gap is documented from garak's own GitHub
  issue tracker (issue #1969, referenced inside `garak-tool-observability`'s README), a
  separate primary source from the blog posts, not from NVIDIA's blog content itself.
  This is worth being precise about in conversation: the claim "garak doesn't score tool
  actions" is well evidenced, but the claim "NVIDIA's blog says this is a known gap" is
  not, based on what was read here.

## The garak question

garak's own README (github.com/NVIDIA/garak, checked directly) states its purpose in
plain terms: it "checks if an LLM can be made to fail in a way we don't want," and it
"probes for hallucination, data leakage, prompt injection, misinformation, toxicity
generation, jailbreaks, and many other weaknesses." Mechanically, it works through
**probes** (classes that generate interactions with an LLM to attempt to trigger a
failure) and **detectors** (classes that identify whether the LLM's output exhibited the
undesirable behavior). The README's own analogy: "If you know `nmap` or `msf` /
Metasploit Framework, garak does somewhat similar things to them, but for LLMs."

Structurally, every detector in that design runs against **what the model generated as
output text**. There is nothing in garak's stated architecture, probe/detector model, or
its own analogy to nmap/Metasploit (both of which report on state, not on an
intermediate action a target silently performed) that claims to observe or score
side-channel actions like whether a tool call actually executed. NVIDIA's own "Defining
LLM Red Teaming" post independently draws this same line when it splits "security red
teaming" (the stack up to inference output) from "content red teaming" (the content
produced at inference time); garak, by its own README's description, sits on the content
side of that split. It was built for and is described as suited to the case where the
harm shows up in what the model says.

That means the `garak-tool-observability` finding, that garak marks a run as clean when
an agent's text reply looks fine but the agent has actually executed an unauthorized
tool call underneath it, sits **inside garak's stated scope as a limitation, not outside
it as a misapplication.** garak was never described, in its own documentation or in
NVIDIA's blog posts, as scoring the technology-stack/action side of an interaction; it
was described as scoring inference-time output. The finding is not "garak is broken" or
"garak fails at something it claims to do." It is "garak's stated scope, once you point
it at something that acts rather than only replies, leaves an entire class of harm
unmeasured, and a clean report from it will look identical whether or not that harm
occurred." That is a precise, defensible, non-hostile way to frame it, and it is
consistent with garak's maintainers' own acknowledgment of the gap (issue #1969,
independently confirmed in `garak-tool-observability`'s README, not sourced from
NVIDIA's blog).

The practical implication for how to talk about this project: don't frame it as "NVIDIA
missed something." Frame it as "garak's design, which NVIDIA's own scope language for
security-vs-content red teaming predicts, means a clean garak report against an agent
tells you less than it tells you against a chatbot, and here is the measured size of that
gap." That is a technical contribution to an open, acknowledged problem, positioned the
way someone who understands the tool's actual design intent would position it.

## Questions worth asking them

1. The 2023 introduction post's four-phase assessment structure (Recon, Technical
   vulnerabilities, Model vulnerabilities, Harm and abuse) and the 2025 AI Kill Chain
   (Recon, Poison, Hijack, Persist, Iterate/Pivot, Impact) both use "Recon" but describe
   different things. Internally, is the Kill Chain treated as a replacement for the 2023
   assessment framework for agentic targets, or do assessors run both depending on
   target type?

2. "Defining LLM Red Teaming" splits security red teaming from content red teaming at
   the inference-output boundary. For an agentic target where a tool call can fire
   before any text is generated, which team or role owns testing the pre-output action,
   and is that currently done with garak, a different internal tool, or ad hoc
   instrumentation?

3. Given the CVE-scoping post's two-part test (does the model fail its intended
   inference function, and is the issue unique enough that a CVE ID helps remediation),
   how does that test apply to an agent framework where the model behaves exactly as
   trained but a downstream tool executes an unauthorized action, since neither
   condition points at the model itself?

4. garak's detectors score generated text. For the Level 2/Level 3 agentic systems
   described in "Agentic Autonomy Levels and Security," is there an internal fork or
   extension of garak (or a separate tool) that captures and scores the actual tool
   invocation trace, not just the reply text, and if so how mature is it relative to the
   public tool?

5. The taint-tracing mitigation named in the autonomy-levels post ("marking an execution
   flow as having received untrusted data...requiring manual re-authorization for
   sensitive tools") sounds like the same source-sink-sanitizer model static analyzers
   use. Is that mitigation implemented as static analysis pre-deployment, runtime
   instrumentation, or both, and where does static analysis's blind spot (cross-function
   or cross-service dataflow) get covered at runtime?

6. The AI Kill Chain's Persist and Iterate/Pivot stages describe cross-session memory
   and agent-to-agent lateral movement. Is there a published or internal benchmark for
   how much persistence/pivot risk shows up in current production agent deployments, or
   is this still primarily a theoretical stage in the framework?

7. The code-execution post treats sandboxing as structurally mandatory over
   sanitization. For teams that can't move to a full sandbox (the WebAssembly proposal
   is one specific architecture), what's the recommended interim control, and has AIRT
   measured how much residual risk sanitization-only leaves in practice?

8. The 2023 post's Table 1 ties assessment activity to ML lifecycle stage
   (Ideation through End-of-Life). For a fast-moving agentic product where the
   "lifecycle" is closer to continuous deployment than discrete stages, has that
   lifecycle mapping been revisited, or does the newer Kill Chain framework function as
   its practical replacement for agentic systems specifically?

# AI security tooling

Six projects that test whether AI systems and the tools built to secure them
actually work. Each one has its own README and its own evidence directory with
the real output behind the numbers.

The connecting idea: a tool that reports no findings looks identical to a tool
that is broken. Several of these exist to tell those two apart.

## The projects

| Project | What it does |
|---|---|
| [garak-tool-observability](garak-tool-observability/) | NVIDIA's garak scanner tests chatbots for security problems. This measures what it structurally cannot see. |
| [ai-supply-chain-audit](ai-supply-chain-audit/) | How much of the popular AI ecosystem ships in a format that runs code when you load it. |
| [rag-poisoning](rag-poisoning/) | How many poisoned documents it takes to reach a user's session, and what happens when one does. |
| [security-analysis-agent](security-analysis-agent/) | A local small model investigates a security question on its own: picks the tool, reads the real result, decides what comes next. |
| [semgrep-llm-rules](semgrep-llm-rules/) | Static analysis rules for the specific code patterns that make LLM applications unsafe, where untrusted text reaches somewhere it should not. |
| [nvidia-methodology-map](nvidia-methodology-map/) | A map of NVIDIA's published AI red team methodology against what their own tooling covers. |

## What none of this claims

- No live production AI system was tested. Everything runs against local models,
  public corpora, or code that ships publicly.
- The garak work measures a structural blind spot in a specific tool version. It
  is not a claim that the tool is bad, and the project says which version.
- The supply chain audit reads file formats and metadata. **No malicious model
  file, pickle, or package was downloaded or loaded**, so nothing here is
  dynamic analysis.
- The Semgrep rules find patterns in code. Matching a pattern is not the same as
  proving an exploit exists, and the rules are documented for what they do and
  do not catch.

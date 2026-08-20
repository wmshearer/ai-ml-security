# How threat actors used AI, 2024 to 2025, from the public reporting

## Question

Between early 2024 and late 2025, OpenAI, Microsoft, Google, and Anthropic each published
reports on threat actors caught misusing their AI models. Read together, do they show a
change in how AI sits in an attacker's workflow? This takes the documented cases from those
reports, organizes them, maps them to the standard frameworks, and measures the shift.

## Sources

Every case comes from a named public report. Nothing here is new intelligence.

- OpenAI, "Disrupting malicious uses of AI by state-affiliated threat actors," Feb 14 2024.
- Microsoft, "Staying ahead of threat actors in the age of AI," Feb 14 2024.
- OpenAI, "Disrupting malicious uses of AI: June 2025."
- OpenAI, "Disrupting malicious uses of AI: an update," October 2025.
- Google GTIG, "Adversarial Misuse of Generative AI," Jan 29 2025.
- Google GTIG, "Advances in Threat Actor Usage of AI Tools," Nov 5 2025.
- Anthropic, "Disrupting the first reported AI-orchestrated cyber espionage campaign," Nov 13 2025.

## The finding

The reports describe three ways AI can sit in an attacker's workflow, and they arrive in
order across the two years.

- **Aid.** The model helps a human, who then does the work. It drafts a phishing email,
  explains a security tool, writes a script. The human is still running the operation.
- **Runtime.** The model is called by the malware or tooling while it runs. It rewrites the
  malware's own code for evasion, or generates the commands the malware executes.
- **Agentic.** The model drives the operation itself across many steps, with a human stepping
  in only occasionally.

Sorted by when each case was documented:

| Period | Aid | Runtime | Agentic |
|---|---|---|---|
| 2024 first half | 5 | 0 | 0 |
| 2025 first half | 6 | 0 | 0 |
| 2025 second half | 1 | 3 | 1 |

Through the first half of 2025, every documented case is AI as an aid. Runtime and agentic
use do not appear at all until the second half of 2025. That is the shift. It is not a
gradual ramp in the reporting. It is a step change in late 2025.

## What the late-2025 cases are

The runtime cases are named malware families that call a model while they run. One rewrites
its own code on a schedule to evade detection. One queries a model to generate its
enumeration and exfiltration commands. One is a ransomware proof of concept that uses a model
to generate its scripts. The agentic case is a single espionage campaign that a vendor
reported was run roughly 80 to 90 percent by an agent across about 30 targets, with operators
using a role-play pretext to get past the model's guardrails.

## Who

Counting distinct actors by the state the reports attribute them to: China leads, followed by
Russia, Iran, and North Korea, with several cases the reports left unattributed. Where a
report did not attribute a state, the case is left unattributed here rather than guessed. That
matters: the table has an "unattributed" column because the sources do, and filling it in
would be inventing attribution the reports did not make.

## Framework mapping

Each case is mapped to MITRE ATLAS technique IDs and to the OWASP Top 10 for LLM Applications
(2025 edition, contemporaneous with the incidents). The aid era is dominated by phishing
(ATLAS AML.T0052) and open-source reconnaissance (AML.T0000). The late-2025 cases add command
generation (AML.T0102), self-replicating prompts (AML.T0061), and, in the agentic case, a
jailbreak (AML.T0054) and excessive agency (OWASP LLM06).

## Limits

This organizes what the reports say. It inherits their attribution and their framing, and it
is only as complete as their disclosures. Vendors report what they caught and chose to
publish, so absence in the data is not absence in the world. The trend is a fair reading of
the reporting available through late 2025, not a claim about everything that happened. Ten
tests lock the case sourcing, the framework IDs, and the shift so none can be quietly changed.

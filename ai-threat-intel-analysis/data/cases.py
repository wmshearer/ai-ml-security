"""Documented cases of threat actors misusing AI models, drawn from public reports.

Every case here comes from a named, published threat-intelligence report by OpenAI,
Microsoft, Google, or Anthropic. Nothing here is invented or inferred beyond what the
source states. Each case records the actor, the sponsor state where the source
attributes one, what the actor did with the model, and the source it comes from. The
analysis in src/ maps these to MITRE ATLAS and the OWASP LLM Top 10 and measures the
shift in how AI is used across 2024 and 2025.

The point of the project is the shift. In early 2024 the reports describe AI as a
productivity aid: writing phishing text, explaining tools, drafting scripts. By late
2025 the reports describe AI inside the malware, called at runtime to rewrite code or
generate commands, and one campaign run almost end to end by an agent. That change is
visible in the data below and is what the analysis measures.

Sources (all public):
  OPENAI_2024  OpenAI, "Disrupting malicious uses of AI by state-affiliated threat
               actors," 2024-02-14.
  MSFT_2024    Microsoft, "Staying ahead of threat actors in the age of AI," 2024-02-14.
  OPENAI_JUN25 OpenAI, "Disrupting malicious uses of AI: June 2025."
  OPENAI_OCT25 OpenAI, "Disrupting malicious uses of AI: an update," October 2025.
  GTIG_JAN25   Google GTIG, "Adversarial Misuse of Generative AI," 2025-01-29.
  GTIG_NOV25   Google GTIG, "Advances in Threat Actor Usage of AI Tools," 2025-11-05.
  ANTHROPIC_25 Anthropic, "Disrupting the first reported AI-orchestrated cyber
               espionage campaign," 2025-11-13.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Case:
    """One documented instance of an actor using an AI model, as a source describes it."""

    actor: str              # the actor name the source uses
    sponsor: str            # attributed state, or "unattributed" / "criminal"
    period: str             # "2024-H1", "2025-H1", "2025-H2"
    uses: tuple[str, ...]   # what the actor did with the model, in the source's terms
    integration: str        # how AI sat in the workflow: "aid", "runtime", "agentic"
    source: str             # source key from the module docstring


# The integration levels, from least to most embedded. This is the axis the trend moves
# along, so it is defined once and ordered.
INTEGRATION_LEVELS = ("aid", "runtime", "agentic")

# aid     the model helps a human who then does the work (drafts phishing, explains a tool)
# runtime the model is called by the malware or tooling while it runs (generates commands,
#         rewrites its own code)
# agentic the model drives the operation itself across many steps with little human input


CASES: tuple[Case, ...] = (
    # ---- 2024 H1: the joint OpenAI + Microsoft disclosure. AI as a productivity aid. ----
    Case("Forest Blizzard", "Russia", "2024-H1",
         ("open-source recon on satellite and radar tech", "scripting and file automation"),
         "aid", "OPENAI_2024"),
    Case("Emerald Sleet", "North Korea", "2024-H1",
         ("recon on think tanks and experts", "spear-phishing content",
          "vulnerability research on public CVEs"),
         "aid", "OPENAI_2024"),
    Case("Crimson Sandstorm", "Iran", "2024-H1",
         ("phishing emails impersonating organizations", ".NET development support",
          "security-tool evasion techniques"),
         "aid", "OPENAI_2024"),
    Case("Charcoal Typhoon", "China", "2024-H1",
         ("tooling and scripting support", "understanding security tools",
          "social-engineering content"),
         "aid", "OPENAI_2024"),
    Case("Salmon Typhoon", "China", "2024-H1",
         ("intelligence-gathering queries", "coding-error troubleshooting",
          "file-concealment technique refinement"),
         "aid", "OPENAI_2024"),

    # ---- 2025 H1: Google's January survey. Still mostly aid, wider actor set. ----
    Case("APT42", "Iran", "2025-H1",
         ("phishing campaigns against defense experts", "reconnaissance",
          "CVE vulnerability research"),
         "aid", "GTIG_JAN25"),
    Case("APT41", "China", "2025-H1",
         ("attempted extraction of the model's own infrastructure details",),
         "aid", "GTIG_JAN25"),
    Case("DPRK IT-worker groups", "North Korea", "2025-H1",
         ("IT-worker cover letters", "infostealer code conversion between languages",
          "sandbox and VM evasion research"),
         "aid", "GTIG_JAN25"),
    Case("DRAGONBRIDGE", "China", "2025-H1",
         ("AI-generated news-presenter videos for an influence operation",),
         "aid", "GTIG_JAN25"),

    # ---- 2025 H1: OpenAI's June report. Criminal and employment-fraud misuse. ----
    Case("IT-worker scheme operators", "unattributed", "2025-H1",
         ("auto-generated resumes and job applications", "recruiting laptop-farm operators"),
         "aid", "OPENAI_JUN25"),
    Case("ScopeCreep operators", "China", "2025-H1",
         ("cyber-operations tooling support",),
         "aid", "OPENAI_JUN25"),

    # ---- 2025 H2: the shift. AI called at runtime inside malware. ----
    Case("PROMPTFLUX (developers)", "unattributed", "2025-H2",
         ("malware calls the model hourly to rewrite its own code for evasion",),
         "runtime", "GTIG_NOV25"),
    Case("PROMPTSTEAL (APT28)", "Russia", "2025-H2",
         ("malware queries a model to generate enumeration and exfiltration commands",),
         "runtime", "GTIG_NOV25"),
    Case("PROMPTLOCK", "unattributed", "2025-H2",
         ("ransomware proof-of-concept uses a model at runtime to generate its scripts",),
         "runtime", "GTIG_NOV25"),
    Case("Russian-speaking malware group", "criminal", "2025-H2",
         ("prototyping a remote-access trojan", "credential-stealer code",
          "detection-evasion crypter code"),
         "aid", "OPENAI_OCT25"),

    # ---- 2025 H2: the far end. An agent running the operation. ----
    Case("GTG-1002", "China", "2025-H2",
         ("agent ran roughly 80 to 90 percent of an espionage campaign across about 30 targets",
          "automated recon, exploit development, credential harvesting, and exfiltration",
          "operators used a role-play pretext to bypass the model's guardrails"),
         "agentic", "ANTHROPIC_25"),
)

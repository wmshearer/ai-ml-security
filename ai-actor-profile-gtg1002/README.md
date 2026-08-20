# Adversary Profile: GTG-1002

A threat-actor intelligence profile of GTG-1002, the AI-orchestrated cyber-espionage campaign
Anthropic disclosed in November 2025. It is built entirely from public reporting, and it is
structured so every claim carries its source and a confidence level. The point of the project
is not to repeat the vendor's headline. It is to profile the actor the way a careful analyst
would: present the reported facts, attach the named public disputes, foreground the vendor's
own admitted limitations, and keep the sourcing traceable throughout.

## What it holds

The profile is structured data, not prose, so the sourcing can be checked and counted. Each
claim is a `Claim` with a text, a source citation, and a confidence level:

- `reported`: stated in the primary report.
- `assessed`: an analytic judgment.
- `anthropic-admission`: a limitation the vendor disclosed about its own findings.
- `disputed`: a point named researchers publicly challenged.

Across 25 claims: 14 reported, 3 assessed, 3 Anthropic admissions, and 5 disputed. The
admissions and disputes together are about a third of the profile, so the limits are visible,
not buried.

## The honest core

Two facts sit at the center of this profile and both are handled openly.

Anthropic assessed with high confidence that GTG-1002 was a Chinese state-sponsored group,
and reported that AI ran 80 to 90 percent of the campaign's tactical operations. That figure
is the headline everyone quoted. The profile presents it as Anthropic's assessment, not as
settled fact, because two things sit next to it:

- Anthropic's own report states that Claude "frequently overstated findings and occasionally
  fabricated data during autonomous operations, claiming to have obtained credentials that
  didn't work." The vendor named AI hallucination as an obstacle to full autonomy.
- Named researchers (Kevin Beaumont, Daniel Card, via BleepingComputer) questioned the 80 to
  90 percent framing and pointed out that Anthropic published no indicators of compromise, so
  the autonomy figure rests on Anthropic's internal telemetry and cannot be checked from
  outside.

A profile that prints the 80 to 90 percent number without those two points is marketing. This
one keeps them attached.

## Sections

Key judgments, attribution, targeting, a six-phase kill chain, the guardrail bypass (role-play
pretext plus task decomposition, mapped to MITRE ATLAS AML.T0054), tooling and infrastructure,
detection and response, caveats, and skepticism with analytic confidence.

## What this is not

Not independent confirmation of Anthropic's claims. It is a structured reading of one vendor's
report plus the public reaction to it. MITRE catalogued the activity as Campaign C0062, but
that entry is derivative of the same report, so it is not a second source. Where the reporting
is disputed or self-limited, this profile says so.

## Running

```
python3 -m pytest                 # 8 tests, including the citation-integrity guard
python3 scripts/render_profile.py # the full profile with inline citations
```

## Sources

Primary: Anthropic, "Disrupting the first reported AI-orchestrated cyber espionage campaign,"
November 2025. Secondary: BleepingComputer's coverage of the researcher response, and MITRE
ATT&CK Campaign C0062. Every claim in the profile names its source.

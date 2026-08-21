# Abuse Program Charter

A portfolio piece: a Trust and Safety / abuse-detection program charter. Not code, not a
detection tool. A written document for a reader deciding whether the author can stand up
and run a program, not just analyze data.

Read the charter: [`docs/CHARTER.md`](docs/CHARTER.md)

## Who this is for

A hiring manager or reviewer evaluating whether I can define a program's mandate,
authority, intake, triage, enforcement, appeals, metrics, and governance, not just build a
detector. The detection and analysis work referenced in this charter as worked examples
lives in sibling portfolio projects: `ai-abuse-triage`, `cib-detection`,
`ransomware-ecosystem`, `llm-abuse-detection`.

## What this is built from

The charter's section structure is adapted from an earlier red team program charter in
this portfolio, which drew its 12-section structure from CREST, TIBER-EU, DoD Instruction
8585.01-P, NIST SP 800-53 CA-8(2), and PTES. Some sections carried over almost unchanged
(authority, scope, metrics, governance). Two red-team-specific sections (Rules of
Engagement, deconfliction with a white cell) were dropped, since neither problem exists
in this domain, and one section with no red-team equivalent (appeals and redress) was
added. The reasoning for each swap is in the charter's introduction.

Verified framework content comes from two research briefs, read directly before drafting:

- DTSP's Best Practices Framework (2021) and its five Commitments
- NIST SP 800-61 Revision 3 (April 2025), which fully superseded Revision 2's four-phase
  incident lifecycle and restructures incident response around CSF 2.0's six Functions
- Google's SRE book, Chapter 14 ("Managing Incidents"), for its four-role incident
  command structure, and its own incident-metrics research on why mean-based statistics
  mislead at realistic volumes

## Source-quality note

Every framework claim in the charter is marked VERIFIED (fetched and read directly by
the research pass this charter draws from), SECONDARY (a reputable summary used because
the primary document couldn't be opened), or GAP (not found at all). Those marks are
carried over unchanged in [`docs/SOURCES.md`](docs/SOURCES.md). Nothing marked SECONDARY
or GAP is presented in the charter as a confirmed fact, and no quotation mark appears in
the charter around text that wasn't verified verbatim from a primary source.

Two corrections this charter gets right, because they're commonly gotten
wrong in published material on this topic: the Google SRE book does not define SEV1
through SEV4 severity levels (this charter's severity tiers are its own design choice,
stated as such), and NIST's current incident-response doctrine (Rev 3, 2025) is not the
well-known four-phase lifecycle from the withdrawn Rev 2.

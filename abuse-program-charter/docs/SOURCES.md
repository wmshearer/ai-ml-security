# Sources

Every framework, standard, or named document cited in `CHARTER.md`, with publisher, exact
title, URL, and a source-quality mark carried over unchanged from the two research briefs
this charter is built from:

- `/home/kali/director/.research/incoming/redteam-charter-frameworks-2026-08-19.md`
- `/home/kali/director/.research/incoming/wave4-program-frameworks.md`

Marks:
- **VERIFIED / PRIMARY**: the brief's author fetched the document directly and quoted or
  paraphrased from the actual text.
- **SECONDARY**: a reputable summary, vendor post, or press account, used because the
  primary document could not be opened in that research pass.
- **GAP**: could not be verified at all in either research pass. Named for transparency,
  not treated as established fact anywhere in the charter.

I did not re-fetch anything myself while writing this charter. Every mark below is
inherited from the brief. If a mark says SECONDARY or GAP, the charter text treats it that
way (hedged language, no quotation marks, no exact figures asserted as certain).

---

## Trust & Safety / abuse-program frameworks

| Framework | Publisher | Document | URL | Mark |
|---|---|---|---|---|
| DTSP Best Practices Framework | Digital Trust & Safety Partnership | "Trust & Safety Best Practices Framework," April 2021 | https://dtspartnership.org/wp-content/uploads/2021/04/DTSP_Best_Practices.pdf | VERIFIED for the General Commitment and Commitment 1 wording, quoted verbatim from extracted PDF text. Commitment 2-5 titles are used but their exact prose was not independently pulled from the document text in the research pass, so the charter treats them as titles only, with no quotation marks. |
| DTSP Safe Framework | Digital Trust & Safety Partnership | "The Safe Framework: Tailoring a Proportionate Approach to Assessing Digital Trust & Safety," December 2021 | https://dtspartnership.org/wp-content/uploads/2021/12/DTSP_Safe_Framework.pdf | VERIFIED (TOC only, not full text) |
| DTSP Safe Framework as ISO/IEC 25389 | DTSP press release | dtspartnership.org press release | https://dtspartnership.org/press-releases/dtsps-safe-framework-published-as-an-international-standard/ | SECONDARY (press release read via search snippet, not fetched). ISO standard text itself is paywalled and was not read. GAP on the ISO document's actual content. Charter mentions this only as a footnote, not as a claim about ISO content. |
| NIST SP 800-61 Revision 3 | NIST | "Incident Response Recommendations and Considerations for Cybersecurity Risk Management: A CSF 2.0 Community Profile," published April 3, 2025 | https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r3.pdf | VERIFIED (PDF downloaded, text extracted directly, including Table 1's crosswalk, quoted verbatim in the brief) |
| NIST SP 800-61 Revision 2 (superseded) | NIST | "Computer Security Incident Handling Guide," 2012 | (withdrawn, not separately cited as current doctrine) | Named only to state it is withdrawn. The four-phase lifecycle it defined (Preparation; Detection and Analysis; Containment, Eradication and Recovery; Post-Incident Activity) is NOT used anywhere in this charter as current guidance. |
| Google SRE Book, Chapter 14, "Managing Incidents" | Google / O'Reilly, freely hosted at sre.google | https://sre.google/sre-book/managing-incidents/ | VERIFIED (fetched directly). Quoted verbatim: "Google's incident management system is based on the Incident Command System, which is known for its clarity and scalability." Four roles (Incident Command, Ops Lead, Communications Lead, Planning Lead) confirmed directly. The book does NOT define SEV1-SEV4 severity levels, and this charter does not attribute severity tiers to this source. |
| NIMS / Incident Command System, Appendix B | FEMA / US DHS | NIMS Appendix B | https://www.fema.gov/pdf/emergency/nims/NIMS_AppendixB.pdf | SECONDARY. The FEMA PDF itself was not opened in either research pass. Structure (single Incident Commander or Unified Command, four General Staff sections: Operations, Planning, Logistics, Finance/Administration) is corroborated across three independent secondary sources but not primary-verified. Charter references NIMS/ICS as lineage only, does not quote its structure as verified fact. |

## Red-team charter structure (reused as methodology, re-pointed at T&S)

| Framework | Publisher | Document | URL | Mark |
|---|---|---|---|---|
| NIST SP 800-53 Rev 5, CA-8 / CA-8(2) | NIST | Control family requiring penetration testing and red-team exercises "in accordance with applicable rules of engagement" | https://csf.tools/reference/nist-sp-800-53/r5/ca/ca-8/ | VERIFIED (exact control text fetched). Used in this charter only as a structural analogy: a program needs a control-style mandate statement, not as a T&S-specific standard. |
| DoD Instruction 8585.01-P | US DoD CIO | Governs DoD Cyber Red Team governance, prioritization, operations, deconfliction, reporting; issued Jan 11, 2024 | https://www.nextgov.com/cybersecurity/2024/01/pentagons-cyber-red-teams-get-clearer-roles-governance/393481/ | PRIMARY content via press coverage; the instruction itself was not confirmed as a directly-hosted public document. Used only as the origin of the "mandate must name governance, prioritization, operations, deconfliction, reporting" pattern this charter's Purpose section borrows. |
| CREST red-team accreditation (CCRTS, CCSAM) | CREST | Red teaming service category page | https://www.crest-approved.org/cyber-service-categories/red-teaming/ | VERIFIED (fetched directly). Cited only as the origin of the "name qualification credentials" pattern used in the Staffing section; T&S does not have an equivalent credential and the charter says so. |
| TIBER-EU | European Central Bank + EU national central banks | Threat Intelligence-Based Ethical Red-Teaming framework | https://www.ecb.europa.eu/paym/cyber-resilience/tiber-eu/html/index.en.html | VERIFIED (fetched directly). Cited only as the origin of the "5-role program with a control function distinct from the operators" pattern this charter's Governance section borrows. |
| PTES (Penetration Testing Execution Standard) | Community/industry standard | Pre-engagement phase description | http://www.pentest-standard.org/index.php/Pre-engagement | Direct site fetch failed in the research pass; content triangulated from cached secondary summaries and a readthedocs mirror. Cited only as the origin of the "explicit scope + explicit exclusions prevents creep" pattern, not quoted directly. |

## Program-metrics and staffing corroboration (used narrowly, flagged where thin)

| Framework | Publisher | Document | URL | Mark |
|---|---|---|---|---|
| Google SRE Book, Chapter 4, "Service Level Objectives" | Google / O'Reilly | sre.google | https://sre.google/sre-book/service-level-objectives/ | VERIFIED (fetched directly). SLI/SLO/error-budget definitions quoted verbatim in the brief. Used in the charter's Metrics section as the source of the SLI/SLO/error-budget framing applied, by analogy, to triage response-time targets. The brief is explicit that this is an analogy the artifact constructs; SRE's book is about production reliability, not security or T&S metrics, and the charter says so. |
| Štěpán Davidovič (Google), "Incident Metrics in SRE" | Google SRE (free report) | https://sre.google/resources/practices-and-processes/incident-metrics-in-sre/ | VERIFIED (fetched directly). Core finding: mean-based incident statistics (MTTR-style) are poorly suited to trend analysis at realistic incident volumes because month-to-month movement in the mean is dominated by noise. This is used in the charter's vanity-metrics subsection to argue against reporting a single mean resolution time. |
| Andrew Jaquith, "Security Metrics: Replacing Fear, Uncertainty, and Doubt" | Addison-Wesley, 2007 | ISBN 9780321349989 | https://www.oreilly.com/library/view/security-metrics-replacing/9780321349989/ | SECONDARY. Book exists and its general good-metric/vanity-metric thesis is corroborated by bookseller listings; the specific four-category taxonomy claimed in some summaries was not independently verified. Charter references the book's general argument (some metrics look impressive and measure nothing decidable) without asserting a specific taxonomy from it. |

## Sibling portfolio projects cited as worked examples

These are the author's own prior work, referenced by name per the task's instruction and
not treated as external frameworks. No source-quality mark applies since these are primary
first-hand results, not third-party claims:

| Project | Path | Fact used |
|---|---|---|
| ai-abuse-triage | `/home/kali/director/projects/ai-abuse-triage` | LLM triaging 1,925 security alerts, pooled Matthews Correlation Coefficient (MCC) of 0.014 (statistically indistinguishable from a coin flip), while scoring 0.695 on one event type and -0.693 on another |
| cib-detection | `/home/kali/director/projects/cib-detection` | Four coordination signals tested; one collapsed to AUC 0.534 against a benign control group once evaluated properly, because it was actually measuring time zone overlap rather than coordination |
| ransomware-ecosystem | `/home/kali/director/projects/ransomware-ecosystem` | A candidate rebrand signal turned out to be a collection artifact: 614 of 16,072 listings shared one scrape date |
| llm-abuse-detection | `/home/kali/director/projects/llm-abuse-detection` | A 7-rule detector where one rule fired zero times across 2,810 test prompts |

## Open items: no source found

- No published Trust & Safety Professional Association (TSPA) operational reference model
  (intake/triage/severity/escalation) was located in either research pass. This charter's
  triage tiers and severity rubric are therefore presented explicitly as the author's own
  design choice, not as an industry-standard structure being followed. This mirrors the
  correction the brief already required for Google SRE severity levels.
- No platform's own published enforcement methodology page (Meta's Community Standards
  Enforcement Report methodology, YouTube's Community Guidelines enforcement report
  methodology) was fetched in either pass. Where the charter's enforcement ladder resembles
  common industry practice, it is not attributed to a specific platform's published
  methodology.
- DTSP's Safe Framework being published as ISO/IEC 25389 is mentioned once, as a footnote,
  because the ISO document content itself was never verified.

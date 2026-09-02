# Sources

Every framework, standard, or named document cited in `METRICS.md`, with
publisher, exact title, URL, and a source-quality mark carried over
unchanged from the research brief this document is built from:

- `/home/kali/director/.research/incoming/wave4-program-frameworks.md`, AREA 4

Marks:
- **VERIFIED / PRIMARY**: the brief's author fetched the document directly
  and quoted or paraphrased from the actual text.
- **SECONDARY**: a reputable summary, book listing, or press account, used
  because the primary document could not be opened in that research pass.
- **GAP**: could not be verified at all in the research pass. Named for
  transparency, not treated as established fact anywhere in this document.

Nothing here was re-fetched while writing this document. Every mark below
is inherited from the brief. Where a mark says SECONDARY or GAP, the
document text treats it that way: hedged language, no quotation marks, no
figures asserted as certain.

---

## Metrics and error-budget framework

| Source | Publisher | Document | URL | Mark |
|---|---|---|---|---|
| Google SRE Book, Chapter 4, "Service Level Objectives" | Google / O'Reilly, freely hosted | sre.google | https://sre.google/sre-book/service-level-objectives/ | VERIFIED (fetched directly). SLI, SLO, SLA, and error-budget definitions in `METRICS.md` Section 5 are quoted verbatim from this chapter. This document states explicitly that the SRE book is about production service reliability, not security metrics, and that applying it to detection quality is an analogy this document constructs, not something the book itself does. |
| Štěpán Davidovič (Google), "Incident Metrics in SRE" | Google SRE, free report | https://sre.google/resources/practices-and-processes/incident-metrics-in-sre/ | VERIFIED (fetched directly). This is the single strongest source in the whole research pass for the metrics argument. Its core finding, quoted in `METRICS.md` Section 4: mean-based incident statistics (MTTR-style) are "poorly suited for decision making or trend analysis" at realistic incident volumes, per a Monte Carlo simulation showing month-to-month movement in the mean is dominated by statistical noise. This document treats that finding as load-bearing, not a footnote, and does not claim the report names one single specific alternative metric beyond percentiles, distributions, and counts, since the brief itself flagged that the exact recommended alternative(s) were not fully captured in its fetch. |
| Andrew Jaquith, "Security Metrics: Replacing Fear, Uncertainty, and Doubt" | Addison-Wesley, 2007, ISBN 9780321349989 | O'Reilly listing: https://www.oreilly.com/library/view/security-metrics-replacing/9780321349989/ | SECONDARY. The brief could not read the book directly (paywalled); only its general thesis (that a good metric must be measurable and support a decision, and that many commonly-reported security numbers, "vanity metrics," fail that test) is carried here, and only as a thesis, not a quotation. This document does not cite or assert Jaquith's specific "four types of metrics" taxonomy, since the brief flagged that taxonomy as single-sourced and unconfirmed. |

## Named and referenced, not load-bearing

| Source | Publisher | Document | URL | Mark |
|---|---|---|---|---|
| NIST SP 800-61 Revision 3 | NIST | "Incident Response Recommendations and Considerations for Cybersecurity Risk Management," published April 3, 2025 | https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r3.pdf | VERIFIED (PDF downloaded, text extracted directly, per the brief's AREA 1). Referenced only to note that Rev 3 restructures incident response onto CSF 2.0's six Functions (Govern, Identify, Protect, Detect, Respond, Recover), and that Rev 2's four-phase lifecycle is withdrawn doctrine. This document does not organize its own reporting cadence around IR lifecycle phases at all, so this citation is background, not a structural borrow. |
| Splunk PEAK Threat Hunting Framework | Splunk (SURGe team) | "Introducing the PEAK Threat Hunting Framework" | https://www.splunk.com/en_us/blog/security/peak-threat-hunting-framework.html | Cited in the sibling `sql-threat-hunting` project's own finding write-up (`docs/FINDING.md`) for the "common is good, uncommon is bad" stack-counting anti-pattern named in `METRICS.md` Section 2's precision-at-operating-point discussion. That citation is that sibling project's own sourcing, reused here by reference, not independently re-verified by this document's own research pass. |

## Explicit gaps, named plainly

- **CIS Metrics (Center for Internet Security).** GAP. The brief could not
  locate or fetch the current "CIS Metrics" release. It confirmed only that
  an older "CIS Security Metrics: Quick Start Guide v1.0.0," dated roughly
  2010, is still reachable as a PDF, but did not read or cite its content,
  since a newer release is known to exist and the 2010 guide would be
  citing withdrawn or outdated material. This document does not cite CIS
  Metrics anywhere as a result.
- **FIRST and ENISA leadership-metrics guidance.** GAP. The brief could not
  find a FIRST-published metrics framework document, and ENISA searches
  surfaced only adjacent NIS2/resilience-metrics material, not guidance
  squarely about leadership reporting metrics. Neither is cited in this
  document. Stated here plainly rather than silently omitted.

## Sibling portfolio projects cited as worked examples

These are the author's own prior work, referenced by name and not treated
as external frameworks. No source-quality mark applies since these are
first-hand results from this portfolio, not third-party claims. Every
figure below was re-checked against that project's own README or
`docs/FINDING.md` at the time this document was written.

| Project | Path | Fact used |
|---|---|---|
| ai-triage-engine | `/home/kali/director/projects/ai-triage-engine` | LLM triaging 1,925 real Windows security events (385 malicious, 1,540 benign), pooled Matthews Correlation Coefficient (MCC) of 0.014, statistically indistinguishable from a coin flip. Stratified by event type: MCC 0.695 on EventID 1 (process creation, 87.5% precision, 61.8% recall), and MCC -0.693 on EventID 13 (registry value set), worse than guessing. Calibration: overall Expected Calibration Error 0.4434; at a self-reported 75% confidence the model was actually correct 19.9% of the time. Run-to-run agreement on 25 repeated alerts, three runs each, at temperature zero: 44.0%. Referenced in `METRICS.md` Section 2 (per-stratum vs. pooled), Section 4 (mean-vs-percentile argument), and Section 7 (calibration and repeatability as unmeasurable-without-a-check examples). Note: this document's task brief referred to this project as "ai-abuse-triage"; the actual sibling project directory holding these exact figures is `ai-triage-engine`. A separate, unrelated project is named `ai-abuse-triage` in this portfolio and reports its own different MCC figure (0.713); that project is not the source of any number in this document. |
| sockpuppet-stylometry | `/home/kali/director/projects/sockpuppet-stylometry` | Pooled AUC 0.677 across three influence operations for a stylometric similarity signal, hiding a GRU-linked operation at AUC 0.918 and an IRA-linked operation at AUC 0.558. Referenced in `METRICS.md` Section 2 as a second, independent instance of the pooled-number failure found in ai-triage-engine. |
| sql-threat-hunting | `/home/kali/director/projects/sql-threat-hunting` | A beaconing detector, tested against a real Torii botnet capture and a benign Philips Hue smart-bulb capture (both from the CTU IoT-23 dataset), ranked the benign bulb's regular firmware-check timer above the botnet's own jittered beacon. Precision at the obvious threshold: 50%. Tightening the threshold drove precision to 0%, not upward. Referenced in `METRICS.md` Section 2 for why precision needs a stated operating point. |
| cib-detection | `/home/kali/director/projects/cib-detection` | A co-timing coordination signal scored AUC 0.592 when compared across different influence operations, but AUC 0.534 (chance) once compared against a benign control group (the Caverlee 2011 social honeypot dataset), because the signal was measuring shared time zone, not coordination. Referenced in `METRICS.md` Section 2 for why a metric needs a benign control group to be a metric at all. |
| llm-abuse-detection | `/home/kali/director/projects/llm-abuse-detection` | A 7-rule prompt-injection/jailbreak detector, tested on a balanced 2,810-prompt set (1,405 real jailbreak prompts, 1,405 ordinary instructions): pooled precision 99.7%, recall 71.8%, F1 83.5%. One rule, leak-extraction, fires zero times across the corpus while still being kept in production as a real, if untested-here, attack category. Referenced in `METRICS.md` Section 1 (the example pack) and Section 3 (rule count is not a capability count). |
| atlas-coverage-map | `/home/kali/director/projects/atlas-coverage-map` | Maps evidence from three sibling projects onto the MITRE ATLAS matrix: 7 of 101 top-level techniques (6.9%), 9 of 16 tactics touched, computed by walking each case's own text rather than asserted by hand. Referenced in `METRICS.md` Section 1 (the example pack) and Section 3 (framework coverage is a measurement, not a target). |
| threat-intel-datamart | `/home/kali/director/projects/threat-intel-datamart` | A star schema over 8 published MISP campaign exports, 8,591 indicators. Referenced in `METRICS.md` Section 1 as the kind of schema the example pack's numbers would be queried from in a real program, not as the source of any specific figure in that pack. |
| ransomware-ecosystem | `/home/kali/director/projects/ransomware-ecosystem` | 614 of 16,072 leak-site listings share a single date (2021-09-09), traced to a likely collection/backfill artifact rather than a wave of real rebrands. Referenced in `METRICS.md` Section 1 (example data-quality caveat) and Section 7 (data-quality artifacts that look like findings). |

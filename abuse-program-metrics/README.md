# Abuse Program Metrics

A portfolio piece: what an abuse-detection or security program reports
upward every month, why those metrics and not the flattering ones, and how
a leader should read them. Not a dashboard, not a website page. A written
deliverable for a reader deciding whether the author can communicate to
executives without either drowning them or lying to them.

Read the pack: [`docs/METRICS.md`](docs/METRICS.md). It leads with the
actual one-page monthly report a program would send, before any of the
explanation behind it.

## The headline point

A pooled number can hide a real capability and a real liability sitting
inside the same average. The sibling `ai-triage-engine` project's LLM
triage classifier scored a pooled MCC of 0.014, statistically no better
than chance, across 1,925 real security events. Broken out by event type:
MCC 0.695 on process-creation events (87.5% precision) and MCC -0.693 on
registry-write events, worse than guessing. One average hid a genuinely
good classifier and an actively harmful one. The sibling
`sockpuppet-stylometry` project found the same shape of failure in a
different domain: pooled AUC 0.677 hid a GRU-linked operation at 0.918 and
an IRA-linked operation at 0.558. This document argues for reporting the
distribution, not the average, and shows the mechanics with `src/metrics.py`.

## Run the tool

```bash
python3 src/metrics.py            # demo: duration stats + strata report
python3 -m pytest tests/ -q       # 20 tests
```

`src/metrics.py` is dependency-free, standard-library Python. It computes
two things a monthly pack needs:

1. **Incident duration stats** (mean, median, p50/p90/p95, count), with a
   warning printed whenever the sample is small enough that the mean is
   unstable. Per Štěpán Davidovič's "Incident Metrics in SRE" (Google), a
   Monte Carlo simulation shows mean-based incident statistics are poorly
   suited for trend analysis at realistic incident volumes.
2. **Per-stratum vs. pooled classifier quality** (Matthews Correlation
   Coefficient, precision, recall), computed both ways with a flag when the
   pooled figure diverges materially from the strata. Run with no
   arguments, it reproduces the real `ai-triage-engine` split above from
   reconstructed confusion-matrix counts that back-solve to the project's
   published figures.

## Source-quality note

Every source claim in `docs/METRICS.md` is marked VERIFIED (fetched and
read directly in the research pass this document draws from), SECONDARY
(a reputable summary used because the primary source couldn't be opened),
or GAP (not found at all). Marks are carried over unchanged in
[`docs/SOURCES.md`](docs/SOURCES.md), including two explicit gaps: no
current CIS Metrics release was located, and no FIRST or ENISA
leadership-metrics guidance was found. Neither is cited as a result.

The SLI/SLO/SLA/error-budget framework in Section 5 is borrowed from
Google's SRE book, which is explicitly about production service
reliability, not security. This document says so directly rather than
implying it is a security-native standard.

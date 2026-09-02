# Leadership Metrics Pack

What an abuse-detection or security program reports upward every month, why
those metrics and not the flattering ones, and how a leader should read them.

This is not a dashboard spec and not a KPI wishlist. It is an argument about
which numbers survive contact with a real program, told through worked
examples from this portfolio, plus one source that should change how most
teams report incident timing: a Google paper showing that the metric almost
everyone leads with (mean time to X) is statistically unreliable at the
volumes a normal team actually sees.

Sourcing, with PRIMARY / SECONDARY / GAP marks, is in `SOURCES.md`. Nothing
here upgrades a mark from that file.

## Contents

1. The one-page monthly pack
2. Every metric: what it measures, how it's computed, what decision it
   supports, how it gets gamed
3. Vanity metrics: what this report will never lead with, and why
4. MTTD and MTTR: why the mean is the wrong statistic
5. Error budgets, borrowed from SRE, for detection quality
6. How to read a bad month
7. What is not measurable, and how to say so upward

---

## 1. The one-page monthly pack

This is the actual page. Everything after this section explains and defends
each line on it. The numbers below are illustrative sample data, formatted
as they would look coming out of a schema like the one in the sibling
`threat-intel-datamart` project (a star schema over indicator and campaign
data) joined against a case/alert fact table. They are not a real month from
any organization. Where a number in this pack is drawn from a real sibling
project instead of illustrative data, it says so in place.

```
DETECTION & ABUSE PROGRAM - MONTHLY REPORT
Month: illustrative sample month                              Prepared: 1st business day

HEADLINE
  Two P1 incidents this month (vs. 1 last month, 3 two months ago).
  Both contained inside SLO. One driven by a new campaign, one by a
  known actor reusing infrastructure we already had signatures for.

DETECTION QUALITY (this is not one number, see why in Section 4)
  Time-to-detect, all P1-P3 incidents (n=34 this month):
    p50: 12 min   p90: 58 min   p95: 3.1 hr   count: 34
    -> below the 30-incident line where a mean would be meaningful noise.
       We report percentiles and count, not an average. See Section 4.

  Rule-level precision (sample of 7-rule detector, illustrative volume):
    6 of 7 rules: 98-100% precision on their own hits
    1 rule (leak-extraction pattern): 0 fires this month, 2,810-prompt
       corpus test volume all-time. Kept in production. Zero fires is
       reported as zero, not omitted. See Section 3.
    -> real per-rule numbers from the sibling llm-abuse-detection
       project: precision 99.7%, recall 71.8%, F1 83.5% pooled across
       7 rules, with the leak-extraction rule firing 0 times across
       2,810 test prompts. That pooled precision number is the kind of
       figure this pack refuses to lead with alone, see Section 2.

ERROR BUDGET (borrowed from Google SRE's SLO framework, see Section 5)
  SLO: 95% of P1 incidents triaged within 30 minutes
  Budget: 5% of P1s may miss that window before this SLO is breached
  Spent this month: 1 of 2 P1s missed the window (analyst was mid-shift-
    change) = 50% of this month's budget on 2 incidents. Small n: this
    is a case to read, not a trend to extrapolate. See Section 6.

COVERAGE (reported, not chased)
  MITRE ATLAS technique coverage from this program's own evidence:
    7 of 101 techniques (6.9%), 9 of 16 tactics touched.
    -> real number, from the sibling atlas-coverage-map project.
       This is a measurement of what our evidence currently shows, not
       a target. Driving it to 50% by writing shallow detections would
       make the number better and the program worse. See Section 3.

DATA QUALITY CAVEAT THIS MONTH
  None material. (In a month where one existed, e.g. the kind of
  single-date collection artifact found in the sibling
  ransomware-ecosystem project, 614 of 16,072 listings sharing one
  date, a scrape artifact, not 40x the real daily volume, it would be
  named here, not silently absorbed into a trend line.)

NOT MEASURABLE THIS MONTH, STATED PLAINLY
  Attacker dwell time before our visibility starts. We only see what
  our sensors cover; we do not know what happened before that. See
  Section 7.

ASKS
  None this month. (A real ask goes here: budget, staffing, a control
  gap, a decision that needs an executive, not a status update dressed
  as a request.)
```

A few things worth noticing about this page before moving on. It is one
page. It has a number that went down (incidents) and a number that has a
gap (one rule at zero fires) sitting next to each other, because both are
true in the same month. It states what is not measurable instead of quietly
leaving it out. Nothing on it is a count of activity (alerts processed,
rules shipped) presented as if it were a count of outcomes.

---

## 2. Every metric: what it measures, how it's computed, what decision it
   supports, how it gets gamed

Each metric is defined in one plain sentence before anything else. The
gaming column is the important one. A metric nobody can game is usually a
metric nobody acts on, but a metric with no gaming column written down is a
metric a leader will trust more than they should.

### Time-to-detect (TTD) and time-to-respond/resolve (TTR)

**What it measures, plainly:** the time between when something bad started
happening and when a human noticed it (detect), and the time between
noticing and closing it out (respond/resolve).

**How it's computed:** timestamp of detection minus timestamp of the
triggering event, per incident; timestamp of resolution minus timestamp of
detection, per incident. Reported as a distribution (percentiles) and a
count, not a single average. Why not the mean is Section 4, in full.

**What decision it supports:** whether triage capacity and detection
coverage are keeping pace with volume; where in the pipeline (alert queue,
analyst load, escalation path) time is actually being lost.

**How it gets gamed:** close incidents early and reopen them as new ones to
reset the clock. Mark something "detected" only once triage picks it up,
even though a queue held it for two hours first, which moves the wait time
out of the metric without moving it out of reality. Both are why the metric
needs a paired queue-wait number and a stated definition of "detected."

### Rule/detector precision and recall, per rule and per stratum

**What it measures, plainly:** precision is "of everything this flagged,
how much was actually bad." Recall is "of everything actually bad, how much
did this catch."

**How it's computed:** per rule, per event type, per data source, not just
pooled across all of them. `src/metrics.py` in this repository computes
both the per-stratum and pooled figures and flags when they materially
disagree.

**What decision it supports:** which specific rule or detector to keep,
retune, or retire; where a detector is safe to route more traffic to and
where it is actively harmful.

**How it gets gamed:** report the pooled number only. A detector that does
real work on one event type and active harm on another can average to a
forgettable "meh." That is exactly the ai-triage-engine result: pooled MCC
0.014 (statistically indistinguishable from a coin flip), while EventID 1
(process creation) scored MCC 0.695 with 87.5% precision, and EventID 13
(registry value set) scored MCC -0.693, worse than guessing. One pooled
number hid a genuinely good classifier and a genuinely harmful one sitting
inside the same average. The sibling sockpuppet-stylometry project found
the identical failure in a different domain: pooled AUC 0.677 across three
influence operations hid a GRU-linked operation at AUC 0.918 and an
IRA-linked operation at AUC 0.558. Two projects, two domains, the same
lesson: an average is a claim about central tendency, not about any one
case a leader might ask about.

### Precision at a stated operating point

**What it measures, plainly:** precision means nothing on its own. It has
to be reported alongside the threshold that produced it, because moving
the threshold changes the number, sometimes in the direction you'd least
expect.

**How it's computed:** report the operating point (the threshold, the
scoring rule, the population it ran against) in the same breath as the
precision figure. Never a bare percentage.

**What decision it supports:** whether to tighten or loosen a detector, and
what that move actually buys.

**How it gets gamed:** report precision without the operating point, so a
reader assumes "tighter equals better" by default. The sibling
sql-threat-hunting project's beaconing detector scored 50% precision at its
obvious threshold, flagging a real botnet and a Philips Hue smart bulb in
equal measure, because the bulb's firmware-check timer was more regular
than the malware's own jittered beacon, jitter the malware authors added on
purpose to avoid looking like a fixed interval. Tightening the threshold
did not fix it. It made it worse: at the tightest threshold tested,
precision fell to 0%, because the only things left standing were more
instances of the bulb. A single number with no operating point stated
invites exactly this kind of "tighten it and it'll get better" instinct,
and here that instinct was actively wrong.

### Coordination / behavioral signal scores (AUC or similar) against a
control group

**What it measures, plainly:** whether a signal actually separates the
thing you're hunting for from ordinary, innocent behavior, as opposed to
separating one bad thing from another bad thing.

**How it's computed:** AUC or an equivalent separation score, computed
twice: once against other instances of the thing being hunted, and again
against a benign control population. Both numbers get reported. Neither
alone is sufficient.

**What decision it supports:** whether a signal is safe to alert on, or
only useful as a comparison between already-confirmed cases.

**How it gets gamed:** skip the control group. The sibling cib-detection
project scored a co-timing signal at AUC 0.592 when compared across
different influence operations, which looked like a workable coordination
signal. Adding a benign control (ordinary Twitter accounts, not
state-linked) dropped it to AUC 0.534, indistinguishable from chance. The
signal had been measuring time zone overlap, not coordination: people in
the same region post in the same hours whether or not anyone is
coordinating them. Without the control group, this would have shipped as a
working detector. A metric without a control group is not a metric. It is
a comparison between two piles of things you already knew were bad.

### MITRE ATT&CK / ATLAS coverage percentage

**What it measures, plainly:** how many named techniques in a framework
have at least one detection or piece of evidence touching them, out of the
framework's total.

**How it's computed:** walk the program's actual detections, rules, or
case evidence and check which technique IDs they touch, then divide by the
framework's total technique count. This should be computed by code that
reruns against the real evidence, not asserted by memory.

**What decision it supports:** where the program's blind spots cluster
(by tactic, by kill-chain stage), so investment can be pointed at the
gap that matters instead of the gap that's easiest to fill.

**How it gets gamed:** write shallow, single-condition rules purely to
claim a new technique ID, with no regard for whether the rule actually
catches anything. Coverage percentage goes up. Nothing gets safer. This
metric belongs in the vanity-metrics section below as much as it belongs
here, because it is exactly as useful as the discipline behind how it was
computed, and exactly as dangerous the moment it becomes a target instead
of a measurement.

### Error budget consumption

**What it measures, plainly:** how much of the allowed miss-rate on an SLO
(service level objective, defined in Section 5) has been used up this
period.

**How it's computed:** (100% minus the SLO target) is the budget; each
missed SLO event consumes a share of it. Tracked daily or weekly, per
Google's SRE book (cited in full in Section 5).

**What decision it supports:** whether to keep shipping changes to a
detection pipeline or pause and stabilize, the same decision an SRE team
makes about a production service.

**How it gets gamed:** narrow the SLO's own definition after a bad month so
the miss no longer counts (redefine what "triaged" means, exclude a
category of incident after the fact). The fix is the same one SRE teams
use: the SLO definition is versioned and changes are visible, not quietly
edited.

---

## 3. Vanity metrics: what this report will never lead with, and why

These numbers are real, computable, and worthless as headlines. Each one is
named here specifically, with what it actually incentivizes.

**Total alerts processed.** Incentivizes generating and processing more
alerts, not better ones. A team that doubles its alert volume with no
change in quality can point at this number going up and call it progress.
It measures throughput of a queue, not the value of what came out of it.

**Number of rules deployed.** Incentivizes writing rules, not rules that
catch anything. The sibling llm-abuse-detection project has 7 rules; one of
them, leak-extraction, fires zero times across a 2,810-prompt test corpus.
A rule count of 7 says nothing about that. Rule count is a count of
artifacts, not a count of capability, and reporting it without also
reporting which rules actually fire and at what quality is reporting
activity as if it were outcome.

**Blocked-attack counts.** Incentivizes counting every block as a win,
which rewards a noisy, over-triggering detector exactly as much as a
precise one, since both produce a large "blocked" number. It also cannot
distinguish a real attack from a false positive that got auto-blocked,
which means the number can go up specifically because the program got
worse.

**Percentage coverage of a framework (ATT&CK, ATLAS, or similar).**
Already covered above as a legitimate measurement of blind spots. As a
headline target, it incentivizes shallow rules written to claim technique
IDs rather than rules written to catch behavior. The sibling
atlas-coverage-map project's real number is 7 of 101 ATLAS techniques,
6.9%, computed by walking real case evidence rather than asserted. That
number is small on purpose; growing it by writing detections that touch a
technique without meaningfully detecting it would make the percentage look
better and the program measurably worse. Framework coverage is a
measurement of where the evidence currently reaches, not a target to chase
upward for its own sake.

What all four have in common: they are easy to move by doing more of
something, and none of them require the something to be good. A metric
nobody can game is usually a metric nobody acts on, because acting on a
metric is exactly what creates the incentive to move it by the cheapest
available means. The response here is not to avoid metrics people can
influence. It's to pair every metric with the gaming column above and
watch for the cheap move, not just the number.

---

## 4. MTTD and MTTR: why the mean is the wrong statistic

Most security programs report Mean Time To Detect and Mean Time To
Respond/Resolve as headline monthly numbers, usually as a single average
figure tracked month over month on a line chart. This section argues, on
primary evidence, that the mean specifically is the wrong statistic for
that job, not just an imperfect one.

The load-bearing source is Štěpán Davidovič's "Incident Metrics in SRE"
(Google), a report built around a Monte Carlo simulation of incident
populations. Its finding, quoted from the research brief that verified it
directly against the primary document: mean-based incident statistics like
MTTR are **"poorly suited for decision making or trend analysis"** at the
incident volumes a normal team actually experiences. The mechanism is not
"the mean has some noise, like any statistic." It's that at realistic
monthly incident counts, month-to-month movement in the mean is dominated
by statistical noise rather than by any real change in how the team or the
systems are performing. A team can get meaningfully better or meaningfully
worse at incident response and the mean can move in the opposite direction
in the same month, purely from which handful of incidents happened to land
in that period.

This matters because most teams see incident volumes on the low end. If a
security program handles, say, 10 to 40 significant incidents a month, that
is squarely inside the range where a mean is close to a random draw
dressed up as a trend line. A single unusually long incident (a P1 that
took six hours because the on-call engineer was mid-flight) can swing a
monthly mean by a wide margin on its own, and a single unusually short one
can swing it back the other way the next month, with nothing about the
program's actual capability having changed either time.

This should be a load-bearing point in how a program reports, not a
footnote next to an average. Concretely, that means:

- **Report percentiles, not a mean.** p50 (median) tells you what a typical
  incident looked like. p90 or p95 tells you what the bad-but-not-worst
  case looked like, which is usually the number that matters for an SLO
  (Section 5). Percentiles are far less sensitive to one outlier incident
  dragging the whole figure around.
- **Report the count alongside every percentile.** A p95 computed from 8
  incidents and a p95 computed from 80 incidents are not the same kind of
  number, even if they come out identical. The count tells the reader how
  much to trust the percentile at all.
- **Flag small samples explicitly, don't just publish the number.** This
  document's own tool, `src/metrics.py`, prints a warning any time the
  incident count for a period is small enough that a mean would be
  unstable, specifically because a chart with a shrinking mean and no
  warning attached reads as good news whether or not it is.
- **Track distributions over time, not one number over time.** A month
  where p50 stays flat but p95 climbs is telling you something different
  from a month where both climb together, and a single mean cannot show
  the difference between those two stories.

None of this claims the mean is useless everywhere, and the brief this
document is built from does not claim that either. It claims specifically
that MTTR/MTTM as a mean, reported as the headline monthly trend figure, is
the wrong tool for that specific job at realistic incident volumes, on
Google's own methodology paper, not on a blog's paraphrase of best
practice.

---

## 5. Error budgets, borrowed from SRE, for detection quality

This section borrows a framework from availability engineering and applies
it to detection quality. It is not a security-native standard, and the
book it comes from is explicitly about production service reliability, not
security metrics. The borrowing is stated here so nobody mistakes SLI/SLO
language for an industry-standard security framework.

From Google's SRE book, Chapter 4, "Service Level Objectives," quoted
directly:

- **SLI (Service Level Indicator):** "a carefully defined quantitative
  measure of some aspect of the level of service that is provided."
- **SLO (Service Level Objective):** "a target value or range of values for
  a service level that is measured by an SLI."
- **SLA (Service Level Agreement):** "an explicit or implicit contract with
  your users that includes consequences of meeting (or missing) the SLOs
  they contain."
- **Error budget:** the book's guidance is that "it is better to allow an
  error budget, a rate at which the SLOs can be missed, and track that on a
  daily or weekly basis." In practice: error budget equals 100% minus the
  SLO target, and the budget gets consumed by permitted misses rather than
  treated as zero-tolerance.

Applied to detection, by analogy, not by any existing security standard:

- **SLI:** "percentage of P1 incidents triaged within 30 minutes of
  detection."
- **SLO:** "95% of P1 incidents triaged within 30 minutes."
- **Error budget:** the remaining 5% is the number of P1s allowed to miss
  that window in a given period before the SLO is considered breached.

The value of this framing over a flat "we hit our target / we missed our
target" report is that it turns a miss into a quantity that accumulates and
can be tracked, the same way an SRE team tracks whether a service is
burning through its reliability budget too fast to sustain its current
pace of changes. A security-detection version of the same discipline: if a
team keeps missing its triage-time SLO, that's a signal to slow down
whatever is consuming analyst attention (a new noisy rule, a staffing gap)
before shipping more detections, in the same way an SRE team pauses feature
launches when a service is burning its error budget too fast.

The limit of the analogy, stated plainly: SRE's error budget assumes failures are
mostly random noise around a stable target, which is a reasonable
assumption for production request latency. A security incident's timing
depends on an adversary's choices, not just internal system behavior, so a
security error budget can be consumed by something structurally different
from noise, like a single new campaign or a genuinely more capable
attacker. A leader reading a security error-budget number should ask which
of those it is before treating a bad month as ordinary variance. That
question is exactly the subject of the next section.

---

## 6. How to read a bad month

This section is written for the executive reading the pack, not for the
team producing it. Its job is to say plainly which movements deserve a
question and which don't, because the wrong instinct in either direction
costs something: reacting to noise burns the team's time explaining
statistical variance, and ignoring a real signal because "it's probably
noise" is how a real degradation gets missed for months.

**Read as noise, most of the time, when the sample is small.** If the
month's incident count is below roughly 30 (this document's tool flags the
exact threshold it uses, and any real program should pick and disclose its
own), a shift in the mean or even the p50 time-to-detect is more likely to
be which incidents happened to occur than a real change in capability.
Ask "how many incidents is this based on" before asking "why did this
number move."

**Read as signal when a percentile moves and the count is large enough to
trust it, especially p90/p95.** A rising p95 with a flat p50 and a healthy
incident count says the typical case is fine but the tail is getting worse,
which is usually an early sign of either a capacity problem (not enough
people to handle the tail) or a new kind of incident the team hasn't built
a fast path for yet. That is worth a question: what's different about the
incidents landing in the tail this month?

**Read as signal when a per-stratum number moves even if the pooled number
doesn't.** A pooled precision or MCC figure that looks stable can be
masking one rule or one detector getting quietly worse while another gets
better, exactly the pattern in the ai-triage-engine and sockpuppet-
stylometry findings above. Ask for the breakdown, not just the total, any
time the pooled trend looks suspiciously flat.

**Read as signal, not routine, when an error-budget miss traces to a named
cause rather than a spread of small delays.** If the SLO miss is "one
incident during a shift change," that's an operational gap worth fixing
(coverage during handoffs) but not evidence the team is failing broadly.
If the miss is "every incident this week ran long," that's a capacity or
tooling problem worth a real conversation, not a one-line note.

**Questions worth asking a program presenting a bad month, in order:**

1. How many incidents is this based on, and does that clear the sample
   size where this number is trustworthy?
2. Is this a pooled number? What does it look like broken out by rule,
   event type, or source?
3. Was there a control group behind any coordination or anomaly score in
   this report, or is a comparison being made only between confirmed-bad
   cases?
4. Is the miss traceable to one cause (a known gap, a specific incident)
   or spread evenly across the period?
5. What changed upstream, an adversary's behavior, a new data source, a
   staffing change, that a metric alone can't show?

**What a leader should not do:** approve or deny a budget request, a
headcount ask, or a tool purchase off a single monthly movement in a mean,
a pooled score, or a coverage percentage, without first getting the answer
to question 1 or 2 above.

---

## 7. What is not measurable, and how to talk about that upward

Some real, important questions do not have a real number attached to
them, and the approach this document argues for cuts both ways: report
what's real, and say plainly when something can't be measured instead of
manufacturing a number that looks like an answer.

**Attacker dwell time before program visibility starts.** A detection
program can only measure what its sensors cover. It cannot know how long
an attacker was present before the first signal any of its tooling could
have seen. Any dwell-time figure that only counts from first-detected-event
is a floor on the real number, not the real number, and should be labeled
as a floor every time it's reported.

**Whether framework coverage equals defensive effectiveness.** A high
ATT&CK or ATLAS coverage percentage is a measurement of where the
program's evidence reaches, not proof that reaching there stops anything.
The practitioner literature on this is consistent even among people who
otherwise use these frameworks heavily: a green heatmap is not validated
capability.

**Confidence scores from an AI or ML component, without a separate
calibration check.** A model's self-reported confidence and its actual
accuracy are two different things, and one does not imply the other. The
sibling ai-triage-engine project measured this directly: its classifier's
overall calibration error (Expected Calibration Error, ECE) was 0.4434,
which is large, and concretely, when the model said it was 75% confident,
it was actually correct only 19.9% of the time. A confidence number
without a calibration check behind it is not evidence of anything. It's an
opinion the model has about itself, and this program's stance is that an
uncalibrated confidence score does not get reported as if it were a
quality metric on its own.

**Run-to-run stability of an AI component.** The same project sent the
same 25 alerts through the same model three times each, with settings
meant to force identical output, and got the same verdict only 44.0% of
the time. Any single evaluation run of a system with that property carries
that much noise baked in, and a one-time snapshot metric from a component
like that should say so rather than imply a single run settles the
question.

**Data-quality artifacts that look like findings.** The sibling
ransomware-ecosystem project found 614 of 16,072 leak-site listings
sharing a single date, which traced to a collection artifact (the tracker's
own start or backfill date), not 24 ransomware groups rebranding at once.
Any number this program reports that depends on a third-party or scraped
dataset carries the same risk, and a real data-quality caveat belongs in
the monthly pack whenever one is found, in the same slot this document's
example page reserves for it, rather than silently corrected out of the
trend.

**How to say all of this upward without sounding evasive:** name the
specific thing that can't be measured, name why (sensor coverage, missing
control group, no calibration check, a known collection artifact), and
pair it with the nearest real proxy if one exists, labeled as a proxy.
"We can't measure X, here's why, and here's the closest thing we can
measure instead" reads as competence. Silence on the same gap, discovered
later by someone else, reads as either negligence or something being
hidden. The difference between the two is entirely in whether the program
said it first.

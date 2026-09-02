# Abuse Detection & Trust and Safety Program Charter

Status: draft, portfolio version
Owner: Head of Trust and Safety (proposed role, see Section 2)
Review cadence: annual, or on any material change to scope, enforcement ladder, or
executive sponsor (see Section 12)

## How this document was built

This charter reuses the section structure and drafting method from a red team program
charter I wrote earlier in this portfolio (see `redteam-charter-frameworks-2026-08-19.md`
in the research archive). That document's 12-section table of contents comes from
CREST, TIBER-EU, DoD Instruction 8585.01-P, NIST SP 800-53 CA-8(2), and PTES. A program
charter is a program charter regardless of whether the team is breaking into systems or
reviewing reports of harassment: both need a stated mandate, a named authority, a defined
scope with exclusions, an intake and case-handling method, an escalation path, a way of
measuring itself, and a maintenance cycle.

Some sections carried over almost unchanged because the underlying problem is the same.
Authority and executive sponsorship, scope and boundaries, metrics, and governance and
review are structurally identical problems in both domains: someone has to own the
mandate, someone has to say what's in and out, and someone has to stop the program from
grading its own homework with numbers that flatter it.

Two sections did not carry over and were dropped rather than adapted:

- **Rules of Engagement for offensive testing.** A red team charter needs a signed
  authorization letter and a list of permitted attack techniques because the activity
  itself, done without authorization, is a federal crime under the Computer Fraud and
  Abuse Act. Reviewing a user report and applying a policy is not an unauthorized-access
  problem. There is no ROE equivalent here. What replaces it is Section 4 (Intake) and
  Section 7 (Enforcement Ladder), which do the actual job of bounding what reviewers are
  allowed to do to an account and on what evidence.
- **Deconfliction with a white cell.** Red team programs need a neutral referee function
  because the blue team might mistake a friendly exercise for a real attack, and someone
  has to be able to call "stop, this is a test" in real time. There is no equivalent
  ambiguity in T&S: a report is a report, not a simulated one. What replaces this section
  is Section 6 (Escalation and Incident Command), which handles a different kind of
  ambiguity: when does a queue of individual cases become a single incident that needs
  a named commander instead of a queue.

One section was added with no red-team equivalent at all: **Section 8, Appeals and
Redress.** A red team engagement doesn't get appealed by the systems it tested. A person
whose account got suspended can be wrongly accused, and the charter has to say what
happens when they push back. This is the section I'd expect a T&S hiring manager to read
first, because it's the part of the job that has no analogy in security testing and is
easy to leave out if you're reasoning from a security-program template without stopping
to ask what's actually different.

---

## 1. Purpose, Mission and Mandate

The program exists to reduce three kinds of platform risk: harm to individual users from
other users or automated abuse (harassment, fraud, exploitation), harm to the platform
from coordinated manipulation (fake engagement, coordinated inauthentic behavior, market
manipulation), and legal and regulatory exposure from failing to act on reportable
content within jurisdictional deadlines.

The program does not exist to maximize enforcement volume, minimize user complaints, or
produce a clean transparency report. Those are downstream effects, sometimes negatively
correlated with each other, and the metrics section (Section 9) says so explicitly.

Mandate statement, adapted from the pattern DoD Instruction 8585.01-P uses for red team
programs (governance, prioritization, operations, deconfliction, reporting), re-pointed at
T&S: this program has standing authority over governance (who sets enforcement policy),
prioritization (which report queues get worked first), operations (how a report becomes a
decision), escalation (how a case becomes an incident), and reporting (what gets measured
and disclosed). Reporting is substituted for the red-team term "deconfliction" because
there is no ambiguous-activity problem to referee in this domain; see the note in the
introduction above.

## 2. Authority and Executive Sponsorship

Executive sponsor: a named VP or C-level executive (Chief Trust Officer, VP Trust and
Safety, or equivalent) who owns the enforcement policy and reports on program health to
the board or an equivalent governance body at least twice a year.

Decision rights, stated concretely rather than left implicit:

| Decision | Who can make it | Who can overturn it |
|---|---|---|
| Individual enforcement action (warning, content removal, account suspension under 30 days) | On-call reviewer, per the enforcement ladder in Section 7 | A senior reviewer or team lead, on appeal (Section 8) |
| Account termination (permanent) | Senior reviewer or above, two-person review for accounts above a defined size or influence threshold | The executive sponsor or a designated policy committee, on appeal |
| New or changed enforcement policy | Executive sponsor, on recommendation from the policy working group | The executive sponsor's own reporting line (legal, CEO) |
| Emergency policy change during an active incident | Incident Commander, time-boxed to the incident, with mandatory post-incident ratification by the executive sponsor within 5 business days | Executive sponsor, at ratification |
| Legal or regulatory takedown request | Legal counsel co-signs with the T&S lead; T&S does not act on a legal request alone | Legal counsel, on their own further review |

The reason this table exists as a table rather than as prose: the single most common
failure mode in T&S programs I've read about is enforcement decisions and policy changes
made by whoever happened to be online, with no record of who actually had the authority to
make the call. A charter that doesn't name the decision-maker for each action type isn't
really a charter, it's a mission statement.

## 3. Scope

**In scope:** abuse types the program actively detects, triages, and enforces against.

- Harassment and targeted abuse between users
- Spam and inauthentic engagement (fake accounts, engagement farming, bot networks)
- Coordinated inauthentic behavior (CIB): networks of accounts acting in a synchronized,
  non-organic way to manipulate visibility, sentiment, or discourse
- Fraud and scams conducted through platform features (payment fraud, romance scams,
  phishing links hosted on-platform)
- Child safety violations (CSAM, grooming indicators), routed to a specialized team with
  its own legal reporting obligations (NCMEC or local equivalent), not handled by general
  queue reviewers
- Platform manipulation for commercial gain (fake reviews, ranking manipulation) where it
  overlaps with the CIB definition above

**Explicitly out of scope for this program**, with the reasoning stated so scope creep has
somewhere to be challenged:

- Content moderation for legal-but-undesirable content (misinformation that isn't fraud,
  offensive-but-lawful speech) is owned by a separate Content Policy team. This program
  handles abuse of the platform's mechanics and abuse of other users, not editorial
  judgment calls about content quality.
- Platform security incidents with no user-abuse component (infrastructure outages,
  credential-stuffing attacks with no downstream user-facing harm) belong to the security
  incident response function, not this program, though the two programs share the
  incident-command structure in Section 6.
- Employment-related conduct (internal HR matters between employees) is out of scope
  regardless of platform used.
- Advertiser policy violations that don't involve user abuse are owned by the ads policy
  team.

A signal needs a control group before it goes into a production detection, not just a
plausible story. The `cib-detection` project in this portfolio built four coordination
signals; one of them collapsed to an AUC of 0.534 against a benign control group, meaning
it performed barely better than random guessing once tested against accounts that
coordinate for innocent reasons, because the signal was actually measuring time zone
overlap, not coordination. Anything entering this program's in-scope detection set has to
clear the same bar: tested against a benign population that could trigger a false
positive for a boring reason, not just against known-bad examples.

## 4. Intake

Reports and signals reach the program through five channels:

1. **User reports.** A user flags content or another account through an in-product
   report flow. Highest volume, lowest average signal quality per report, because most
   reports are either duplicates or a dispute the user has already lost (a blocked user
   reporting the person who blocked them).
2. **Automated detection.** Rule-based and model-based systems that flag accounts or
   content without a human report. Highest signal-to-noise variance: a single detector
   can range from excellent to worthless depending on the rule, which is why Section 9
   requires per-rule reporting, not a single blended detector accuracy number.
3. **Trusted flaggers.** A defined list of external partners (NGOs, law enforcement
   liaisons, industry information-sharing groups) whose reports get an expedited queue
   because they've been vetted for accuracy over time. Trusted flagger status is
   reviewed annually and can be revoked.
4. **Legal and regulatory requests.** Takedown demands, subpoenas, and regulatory orders.
   Always co-reviewed with legal counsel per the decision-rights table in Section 2.
   These carry externally imposed deadlines (for example, an EU Digital Services Act
   notice-and-action deadline) that this program's own SLA targets in Section 5 must
   accommodate, not override.
5. **Internal escalation.** An employee anywhere in the company can escalate a suspected
   abuse pattern directly to the program, bypassing the user-report flow. This exists
   because employees sometimes see abuse patterns (in support tickets, sales
   conversations, internal dashboards) before any user reports them.

**Deduplication and queueing.** Reports about the same account or the same coordinated
cluster are merged into a single case before triage, not queued as separate items, so
that a viral pile-on report doesn't consume ten reviewer-hours for what is one decision.
Merge logic runs on account ID and content-hash matching at minimum; anything fuzzier
(behavioral clustering) is itself a detection signal that needs the same control-group
testing described in Section 3, not an assumption that clustering is automatically
correct.

**Data quality gate before any signal enters the queue as a scored risk factor.** A
signal derived from a bulk data source has to be checked for collection artifacts before
it's trusted, not just before it's deployed. The `ransomware-ecosystem` project in this
portfolio found that a candidate rebrand signal, which looked like evidence of criminal
groups relaunching under new names, was actually a scraping artifact: 614 of 16,072
listings shared a single collection date, meaning the pattern was in how the data was
gathered, not in the underlying phenomenon. The same check applies to any bulk feed
feeding this program's intake: check the distribution of a proposed signal's supporting
metadata (dates, sources, collection batches) for exactly this kind of clustering before
treating it as a real pattern.

## 5. Triage Tiers and Severity Rubric

Neither DTSP's framework nor NIST SP 800-61r3 nor the Google SRE book publishes a
severity-tier scale for Trust and Safety casework, so the tiers below are this program's
own design choice, stated as that and not attributed to an external standard. This
mirrors a correction that matters twice in this document: the Google SRE book's incident
management chapter does not define SEV1 through SEV4 severity levels either, despite that
being widely repeated online as if it came from the book. What the book actually gives is
qualitative criteria for deciding an incident needs declaring at all: a second team has to
get involved, the issue is customer-visible, or it's unsolved after an hour of analysis
(quoted from the SRE book chapter, see Section 11 and `SOURCES.md`). This charter borrows
that declaration logic in Section 6 and builds its own severity tiers here, separately.

| Tier | Definition | Example | Response-time target | Who reviews |
|---|---|---|---|---|
| Tier 1 (Critical) | Imminent physical harm, child safety, active mass-coordinated attack in progress | Grooming indicator on a minor's account; live CIB network actively manipulating a real-time event | Acknowledge within 15 minutes, action within 1 hour, 24/7 on-call | Specialized team (child safety) or Incident Commander (CIB), not general queue |
| Tier 2 (High) | Ongoing harm to a specific person, high-confidence fraud, high-reach account | Targeted harassment campaign against one user; a confirmed romance-scam account with active conversations | Acknowledge within 1 hour, action within 8 hours, business-hours plus on-call | Senior reviewer |
| Tier 3 (Standard) | Policy violation with no ongoing active harm at report time | Spam account with no current victim contact; a single instance of harassment already stopped | Acknowledge within 24 hours, action within 3 business days | General queue reviewer |
| Tier 4 (Low) | Low-confidence or low-impact reports, likely duplicate or already resolved | A report against an account already suspended; a borderline case with weak evidence | Acknowledge within 5 business days, may be closed without individual action if part of a batch pattern | General queue reviewer, batchable |

Tier assignment at intake is a first pass, not a final judgment, and is a specific place
this program expects to be wrong sometimes: a Tier 3 report can be re-tiered to Tier 1 if
new evidence surfaces during review. The rubric exists to set a default response-time
commitment the program can be held to, not to lock every case into its first
classification.

## 6. Escalation and Incident Command

A case escalates from an individual review item to a program-level incident when any one
of three conditions is met, adapted directly from the Google SRE book's declaration
criteria for a production incident, re-pointed at abuse response: a second team needs to
get involved (legal, communications, a platform engineering team to ship a mitigation), a
pattern is visible to a meaningful number of users or to the press, or it remains
unresolved after a defined analysis window (2 hours for this program, versus the SRE
book's 1 hour, because most T&S cases don't have the same page-is-down urgency and a
shorter window would generate false escalations).

When a case becomes an incident, four roles activate, following the same structural split
the Google SRE book documents (drawn originally from the Incident Command System used in
emergency management, which the SRE book cites as its own lineage):

- **Incident Commander.** Holds the overall state of the incident, decides tier and
  priority calls that cut across teams, is the single point of authority for the
  duration. For a T&S incident, this is a senior T&S lead or the executive sponsor for a
  Tier 1.
- **Operations Lead.** The only role authorized to take enforcement action during the
  incident (suspend accounts, remove content, roll out a policy exception). This mirrors
  the SRE book's rule that the Ops lead is the only group allowed to modify the system
  during an incident; here, "the system" means live accounts and content, so this
  restriction also functions as an internal control against unauthorized mass actions
  during a high-pressure event.
- **Communications Lead.** Owns the single external and internal narrative: what users
  are told, what press is told, what internal stakeholders are told. One voice, so
  different teams don't publish different explanations of the same event.
- **Planning Lead.** Tracks longer-running work the incident generates: policy changes
  that need ratification per Section 2's table, follow-up detections to build, and the
  post-incident writeup.

This four-role split is Google's own adaptation of the Incident Command System (ICS),
which in its original FEMA/NIMS form uses four General Staff sections (Operations,
Planning, Logistics, Finance/Administration) under a single Incident Commander. Google's
version collapses Logistics and Finance/Administration, which rarely apply to a software
or content incident, and adds a dedicated Communications role that ICS instead places
under the Incident Commander's own command staff. This charter follows Google's four-role
version for the same reason Google does: logistics and finance/admin sections are rarely
the bottleneck in this kind of incident, and a dedicated communications function is.

## 7. Enforcement Ladder and Consistency

Enforcement actions available, in ascending order of severity:

| Action | What it does | When proportionate |
|---|---|---|
| Warning | Notifies the account of a violation, no functional restriction | First offense, low severity, ambiguous intent |
| Content removal | Removes the specific violating content only | Clear violation, account otherwise in good standing |
| Feature restriction | Disables a specific capability (posting, messaging, monetization) for a fixed period | Repeated violations of the same type, or a violation tied to a specific feature |
| Reach reduction | Reduces algorithmic distribution without removing content or notifying the user | Borderline policy violations where full removal is disproportionate but continued full distribution isn't appropriate either |
| Temporary suspension | Full account suspension for a fixed period (24 hours to 30 days) | Tier 2 violations, or repeated Tier 3 violations |
| Permanent termination | Account permanently disabled | Tier 1 violations, or a demonstrated pattern of repeated severe violations after prior enforcement |

Proportionality is judged on three factors, applied the same way every time: severity of
harm, whether this is a first violation or a repeat, and evidence confidence. A ladder
only means something if the same facts produce the same outcome for different accounts,
so consistency is enforced by two mechanisms rather than by reviewer judgment alone:

- **Precedent lookup.** Before issuing an action above Tier 3 severity, the reviewer
  checks a precedent database of prior decisions on matching fact patterns. A decision
  that departs from precedent requires a one-line justification recorded with the case.
- **Calibration review.** A sample of closed cases is re-reviewed monthly by a second
  reviewer, blind to the original outcome, specifically to measure disagreement rate
  between reviewers on the same facts. A rising disagreement rate is itself a metric
  reported in Section 9, not something the program waits to notice informally.

## 8. Appeals and Redress

This section has no equivalent in the red team charter this document is based on. A red
team engagement's target doesn't get to appeal being tested. A person whose account was
suspended can be innocent, and the program has to build for that possibility as a normal
operating case, not an edge case.

Every enforcement action at Tier 3 severity or above (Section 5) comes with a stated
appeal right and a plain-language explanation of what policy was violated, communicated
at the time of action, not only if the user asks.

**Appeal process:**

- The user submits an appeal through a defined channel, separate from the original report
  channel, with a hard cap on how much new evidence they can submit (to prevent an appeal
  from becoming an unbounded second investigation).
- The appeal is reviewed by someone who did not make the original decision. This is a
  hard rule, not a preference: the same reviewer re-reviewing their own decision is not an
  appeal, it's a second opinion from an interested party.
- Target: appeal decided within 5 business days for Tier 3 and below, within 2 business
  days for Tier 2, within 24 hours for Tier 1 (child safety appeals route through a
  specialized legal-compliance path with its own timeline, not this one).
- The outcome of an appeal (upheld, overturned, partially overturned) is logged and rolls
  into the calibration review in Section 7: a reviewer or a specific detection rule with
  an unusually high overturn rate is a signal that rule or reviewer needs review, not
  something to note and move past.

**What redress does not include:** this program does not compensate users for enforcement
actions later found to be wrong, beyond reversing the action itself and restoring access.
Financial or reputational redress beyond reversal is a legal and policy question outside
this program's mandate, referred to legal counsel per Section 2 if a user raises it.

## 9. Metrics

Metrics are split into two categories on purpose: what this program reports because it's
decision-useful, and what it will not report as a headline number because it's a vanity
metric that looks good without being decidable.

**Reported metrics:**

- Time-to-first-action per severity tier, measured against the targets in Section 5, as
  a distribution (median and 90th percentile), not a single mean. Google's own SRE
  research on incident metrics found that mean-based incident statistics are poorly
  suited to trend analysis, because at realistic incident volumes month-to-month
  movement in a mean is dominated by statistical noise rather than real signal. That
  finding was published about production incidents, not T&S casework, but the underlying
  statistical problem, a mean hiding the shape of the underlying distribution, applies
  here too and this program reports accordingly.
- Appeal overturn rate, per detection rule and per reviewer, not blended into one number.
- Per-rule precision and recall for every automated detector, reported individually, not
  pooled. The `ai-abuse-triage` project in this portfolio is the clearest evidence in this
  portfolio for why pooling is misleading: an LLM triaging 1,925 security alerts scored a
  pooled Matthews Correlation Coefficient of 0.014, statistically no better than a coin
  flip, while scoring 0.695 on one event type and -0.693 (worse than random, in the wrong
  direction) on another. The pooled number hid two completely different systems bolted
  together and reported as one. This program will not publish a single blended accuracy
  figure across dissimilar abuse types for the same reason.
- Detection rule coverage and retirement. The `llm-abuse-detection` project in this
  portfolio found a 7-rule detector where one rule fired zero times across 2,810 test
  prompts. A rule with zero fires over a meaningful volume is either catching something
  real but rare enough to need a much larger sample to know, or it's dead weight
  inflating a coverage count. This program reviews every detection rule's fire rate
  quarterly and retires or re-tests rules with no fires over the review window rather
  than leaving them in a coverage count indefinitely.

**Explicitly not reported as a headline metric, and why:**

- **Total enforcement actions taken.** A rising count can mean the program is catching
  more abuse or that it's over-enforcing on ambiguous cases. Without a stable denominator
  (total reports, total active accounts) this number moves for reasons that have nothing
  to do with program health and it will not be presented as a success indicator on its
  own.
- **Average (mean) resolution time as a single number**, for the reason stated above.
- **Blended detection accuracy across dissimilar abuse types**, for the reason the
  `ai-abuse-triage` project demonstrates above.
- **Raw ATT&CK-style "coverage" counts of abuse types with a rule mapped to them.** A
  rule existing for an abuse type is not evidence the rule works; see the rule-retirement
  point above.

This program's metrics reporting is designed to sit alongside, not duplicate, the
sibling metrics-and-detection-quality work already done in this portfolio
(`ai-abuse-triage`, `cib-detection`, `llm-abuse-detection`). Those projects are the
worked evidence for why this section is written the way it is.

## 10. Staffing Model

Roles: general queue reviewers (Tier 3/4 volume), senior reviewers (Tier 2 and appeals),
a specialized child-safety team with its own legal training and reporting obligations, a
policy working group that drafts and maintains the enforcement ladder, and the
Incident Command roles from Section 6, which are trained rotations rather than
full-time positions.

**Reviewer wellbeing** is a real, documented occupational-health issue in content
moderation and abuse review work, not a soft add-on to a staffing plan. Reviewers are
regularly exposed to distressing material (child safety content, graphic harassment,
violent imagery) as a condition of the job. This program commits to concrete practices,
not a general wellness statement:

- Mandatory rotation off high-severity queues (child safety, graphic content) on a fixed
  schedule, not left to individual discretion or manager judgment about who "seems fine."
- Access to specialized mental health support with experience in trauma exposure from
  content moderation work specifically, not generic employee assistance program access
  as the only resource.
- Caseload caps per shift for high-severity queues, reviewed if overturn rates or error
  rates rise on a reviewer's queue, since fatigue is a plausible contributor to
  inconsistent decisions and should be checked before assuming a reviewer needs more
  training.
- Exit interviews and workload data reviewed specifically for wellbeing-related attrition,
  reported to the executive sponsor, not folded silently into general attrition
  reporting.

I'm treating this briefly and specifically rather than at length, because padding this
section with general wellness language would undercut the point: a staffing model that
doesn't name a rotation schedule and a caseload cap isn't actually addressing the problem.

## 11. Governance, Review Cadence, and Charter Maintenance

This charter is reviewed annually by the executive sponsor and the policy working group.
It is also reviewed, out of cycle, on any of: a change in executive sponsor, a material
change to the enforcement ladder, a regulatory change that alters legal obligations
(Section 4), or a Tier 1 incident's post-incident review recommending a charter change.

Amendment authority: only the executive sponsor can approve a change to the decision-
rights table in Section 2 or the scope definition in Section 3. The policy working group
can propose changes to the enforcement ladder (Section 7) and severity rubric (Section 5)
subject to the executive sponsor's sign-off. No single reviewer or team lead can change
scope or the enforcement ladder unilaterally, including during an active incident; the
Incident Commander's emergency authority in Section 2's table is explicitly time-boxed
and requires ratification precisely so an incident-time exception doesn't become a
permanent, undocumented policy change by default.

## 12. Framework Alignment

This table maps the charter's sections against the two verified external frameworks this
program most directly answers to: DTSP's five Commitments (industry self-regulatory,
company-published) and NIST SP 800-61r3's six CSF 2.0 functions (federal guidance,
published April 2025, current). DTSP is a partnership of member companies publishing its
own commitments, not an independent standards body with enforcement power; that
distinction is worth stating plainly rather than implying DTSP carries NIST's kind of
authority.

| Charter section | DTSP Commitment | NIST SP 800-61r3 CSF 2.0 function |
|---|---|---|
| 1. Purpose and Mandate | General Commitment: "Account for content- and conduct-related risk in the domains of product development, governance, enforcement, and improvement, and assign responsibilities and resources in each domain." (quoted verbatim from the DTSP framework) | Govern |
| 2. Authority and Executive Sponsorship | Product Governance | Govern |
| 3. Scope | Commitment 1: "Identify, evaluate, and adjust for content- and conduct-related risks in product development." (quoted verbatim) | Identify |
| 4. Intake | Product Governance | Identify, Detect |
| 5. Triage Tiers and Severity Rubric | Product Enforcement | Detect |
| 6. Escalation and Incident Command | Product Enforcement | Respond |
| 7. Enforcement Ladder and Consistency | Product Enforcement | Respond, Protect |
| 8. Appeals and Redress | Product Enforcement (no DTSP commitment addresses redress specifically; this is this charter's own addition, see the introduction) | Recover |
| 9. Metrics | Product Improvement, Product Transparency | Identify (Improvement Category, per Rev 3's Table 1 crosswalk) |
| 10. Staffing Model | Product Governance | Govern |
| 11. Governance and Maintenance | Product Governance | Govern |

A note on the right-hand column, because getting this wrong is a common mistake in
published material on this topic: NIST SP 800-61 Revision 3 (April 2025) fully
superseded Revision 2. Rev 2's well-known four-phase incident lifecycle (Preparation;
Detection and Analysis; Containment, Eradication and Recovery; Post-Incident Activity) is
withdrawn doctrine, not current guidance, even though a large amount of published
material online, including recent vendor blog content, still presents that four-phase
model as if it were NIST's current framework. Rev 3 restructures incident response
entirely around CSF 2.0's six Functions (Govern, Identify, Protect, Detect, Respond,
Recover) and explicitly crosswalks the old four phases onto the new functions in its
Table 1, rather than continuing to use the old phases as its own structure. This
charter's mapping above uses the CSF 2.0 functions directly, and where Rev 3's own
crosswalk placed something (for example, Post-Incident Activity mapping to the Identify
function's Improvement Category), this charter follows that placement rather than
inventing its own.

---

Sources for every claim above, with primary/secondary/gap marking preserved from the
research briefs this charter was built from, are in `SOURCES.md`.

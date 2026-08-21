# Post-incident review: the Nx s1ngularity compromise

**Subject.** Compromise of the Nx build system's npm publishing pipeline,
August 2025, resulting in malicious package versions that harvested developer
credentials.

**Why this incident.** It is one of the few AI-adjacent security incidents with
a vendor-authored postmortem *and* a security advisory carrying minute-level
timestamps. Most AI incidents are reconstructed from press coverage. This one
the vendor documented themselves.

**What I am doing here.** Running a real incident against the four playbooks in
this repo and reporting where they hold and where they do not. A playbook nobody
has exercised is a document, not a capability.

**Sources.** Everything below comes from two primary sources:

- Nx security advisory GHSA-cxm3-wv7p-598c, published August 27 2025, 1:53 AM EDT
- Nx postmortem blog, published September 5 2025

Where I state something the sources do not, I say so.

---

## What happened

**August 21, 4:31 PM EDT.** A pull request is merged adding a GitHub Actions
workflow with a bash injection flaw. The workflow used `pull_request_target`,
which runs with repository write permissions and access to secrets, against
content the submitter controls.

**August 21, 10:48 PM EDT.** A security researcher posts about the injection
flaw publicly on X. Nx does not see it yet.

**August 22, 3:17 PM EDT.** Nx notices the post, roughly 16 hours later, and
begins investigating.

**August 22, 3:45 PM EDT.** The vulnerable workflow is reverted. The advisory's
own wording is careful here: this was reverted "which we believed at the time
would prevent the vulnerable pipeline from being used."

That belief was wrong, and the reason is the single most transferable lesson in
this incident. Reverting the workflow on the main branch did not remove it from
**existing pull request branches**, which still carried the vulnerable version.

**August 24, 4:50 PM EDT.** The attacker commits, exfiltrating the npm token to
a webhook. **5:04 PM.** A PR carrying that commit triggers the validation
workflow. **5:11 PM.** The publish workflow is deleted from the audit logs.

**August 26, 6:32 PM EDT.** Malicious versions begin publishing. Over the next
two hours, eight versions of `nx` and several `@nx/*` packages go out.

**August 26, 8:30 PM EDT.** Two GitHub issues are filed by users. This is the
detection. Not monitoring, not alerting. Users noticed.

**August 26, 9:58 PM EDT.** A team member sees the issue. 88 minutes after the
first user report, and 3 hours 26 minutes after the first malicious publish.

**August 26, 10:44 PM EDT.** npm removes the affected versions and revokes
publish tokens.

**August 27, 11:57 AM EDT.** All packages moved to 2FA and Trusted Publishers
using OIDC. Token-based publishing is eliminated.

## What the payload did

The postmortem's description, in full:

> scanned user systems for sensitive data, attempted to use local AI tools (like
> Claude and Gemini), and uploaded the results to a public GitHub repo via the
> GitHub CLI

**The word "attempted" matters and I am not going to smooth it over.** The
vendor does not say the AI tools succeeded, and does not describe the mechanism.
Widespread reporting of this incident describes the malware as "using AI CLI
tools to find secrets." The primary source says attempted. Those are different
claims and only one is sourced.

Nx also withheld step-by-step payload detail deliberately. That is a defensible
disclosure decision and it means a PIR written from public sources has a real
gap in it.

---

## Running it against the playbooks

**None of the four playbooks in this repo would have helped.** That is the honest
result and it is worth more than a forced fit.

| Playbook | Applies? | Why not |
|---|---|---|
| 01 Direct prompt injection | No | No assistant was manipulated. AI tools were the payload's instrument, not its target. |
| 02 Context extraction | No | No model context was extracted. |
| 03 Agent tool abuse | Partially, by analogy only | The payload invoked local AI CLIs on developer machines. But those tools were the attacker's, running with the developer's own permissions. No agent was hijacked. |
| 04 Indirect injection | No | No retrieval corpus involved. |

**What this incident actually was: a software supply-chain compromise** in which
AI tooling appeared as an instrument. Calling it an AI security incident because
AI CLIs are named in the payload would be pattern-matching on a keyword.

**The finding for the playbook set:** it covers AI systems as *targets* and has
nothing for AI tooling as *attacker capability*. A developer machine with an
authenticated AI CLI installed is a credential-bearing endpoint that can be
driven programmatically. That is a fifth scenario the set does not have.

---

## What an incident commander faced

**Decision 1: how to respond to a public vulnerability report with no reporting channel.**
The flaw was disclosed on X, not to Nx. There was no SECURITY.md. The 16-hour
delay is a direct consequence, and the fix afterwards was to create one.

**Decision 2: whether the revert was sufficient.** Reverted at 3:45 PM on the
22nd, exploited on the 24th. The advisory says they believed it was enough.
Verifying that belief would have meant asking where else the workflow existed,
which is a different question from whether it was removed from main.

Against this repo's own validation methodology, this is a precondition check
that was not run. The assumption "reverting removes the path" was load-bearing
and untested.

**Decision 3: revoke all tokens or targeted ones.** Nx revoked all publishing
tokens at 11:57 PM, breaking CI for everyone. Correct call. Targeted revocation
requires knowing exactly which token was taken, and at that moment they did not.

**Decision 4: what to disclose about the payload.** They published a postmortem
with the mechanism omitted. Reasonable, and it costs downstream defenders detail
they would use.

---

## What is not publicly known

- How many machines were compromised. Third parties published credential counts;
  Nx did not confirm them, and I am not repeating unconfirmed figures.
- Whether the AI CLI invocation succeeded, or what it was asked to do.
- Whether any downstream breach followed from the harvested credentials.
- What alternatives were considered in real time. A postmortem is written with
  hindsight and shows decisions, not deliberation.

## What transfers

**Detection came from users.** Three and a half hours of malicious packages on
npm, found by two people filing GitHub issues. For any project publishing
artifacts others install, the question is whether an unexpected publish would
generate an alert. Here it did not.

**A revert is not a removal.** The vulnerable workflow persisted in PR branches
after being reverted from main. Nx's eventual fix was to rebase every outdated
branch, at 3:14 PM on the 27th.

**Token elimination beat token rotation.** They rotated first, then removed the
credential class entirely by moving to OIDC. The second fix is the one that
holds.

**"Attempted" is not "did".** The most-repeated version of this incident has the
payload successfully driving AI assistants to hunt for secrets. The vendor wrote
"attempted to use", described no mechanism, and reported no outcome. The retelling
is one word stronger than the source, and that word is the whole claim.

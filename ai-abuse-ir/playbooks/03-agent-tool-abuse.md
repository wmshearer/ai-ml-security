# Playbook 03: Agent hijacking and unauthorized tool invocation

**Scenario.** An assistant with the ability to take actions is manipulated into
taking one the requesting user was not entitled to.

**Why this playbook exists.** This is the most serious of the four, because it
crosses from what the model *says* to what the system *does*.

Against my test assistant, two separate tool abuses succeeded:

- an unauthorized email send
- an unauthorized file read

Both mapped to OWASP LLM03:2026 Excessive Agency and MITRE ATLAS AML.T0053,
AI Agent Tool Invocation.

**The structural problem.** In a text-only injection, the damage is a bad reply.
Here the model holds credentials, and a hijacked model spends them. The
assistant's service identity is usually broader than any individual user's, so
a successful hijack is a privilege escalation whether or not it was designed as
one.

---

## Detect (DE)

**This is the one AI-abuse class with genuinely reliable detection**, because
tool calls are discrete, loggable events with arguments. Unlike text output,
there is no ambiguity about whether one happened.

**Signals, all of them actionable:**

1. **A tool call whose arguments fall outside the requesting user's scope.**
   Reading a path they cannot read, emailing a domain outside policy. This is a
   direct authorization comparison, not a heuristic.
2. **A tool call with no plausible relationship to the user's request.** Requires
   correlating request text to tool invocation, which is harder, but a file read
   during a password-reset conversation is visible.
3. **Volume or rate anomalies.** Tool calls per session above the normal
   distribution.
4. **Tool call sequences.** Read then send is a different risk shape than either
   alone, and worth alerting on as a pair.

**The detection this class deserves and often lacks:** log every tool invocation
with the calling user, the resolved arguments, the authorization decision, and
the outcome. Most of the difficulty in these incidents is reconstructing what the
agent actually did, and that is a logging decision made long before the incident.

## Respond (RS)

**Order matters here more than in the other playbooks.**

1. **Disable the tool, not the assistant, if you can do it that granularly.**
   Keeps the service up while closing the specific path.
2. **Enumerate every tool call in the affected session.** Then widen: the same
   technique against other sessions in the same window.
3. **Treat every action taken as real and attributable to the attacker.** An
   email sent was sent. A file read is disclosed. Recovery is about the effects
   of the actions, not about the model.
4. **If the tool holds a credential, rotate it.** The agent's service identity
   should be assumed exercised by whoever controlled the agent.
5. **Only then decide about the session.**

## Recover (RC)

1. Undo what can be undone. Recall messages, revoke created access, delete
   written data.
2. What cannot be undone becomes disclosure, and disclosure is a legal and
   privacy decision.
3. Re-enable the tool only once authorization moved to the calling user's
   permissions.

## Identify, Improvement (ID.IM)

**The review question is not "how did the injection get through."** Injection
will get through. The question is why a successful injection could reach a tool
call the user was not entitled to make.

If the answer is that the agent authorizes as itself rather than as the user,
that is the finding, and it was true before the incident.

## Govern (GV) and Protect (PR), before the next one

- **Every tool call authorizes against the calling user's permissions.** This is
  the single control that makes this incident class survivable. With it, a
  hijacked agent can do exactly what the user could already do, which is not an
  incident.
- Tools that perform irreversible or outward-facing actions require confirmation
  from the user, out of band from the model's own reasoning.
- Tool inventory is maintained. You cannot scope what you have not enumerated.

## What this playbook cannot tell you

Whether the model "intended" the call. That question does not have an answer and
does not need one. The call happened, under whose authority, with what arguments.
Those are the facts, and they are all recoverable from a log if you kept one.

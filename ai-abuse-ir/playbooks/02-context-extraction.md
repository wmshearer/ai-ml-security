# Playbook 02: Hidden context and secret extraction

**Scenario.** A user gets the assistant to reveal its system prompt, or a secret
held in that prompt, or content from documents belonging to another user.

**Why this playbook exists, and the detail that matters most.** Against my test
assistant, a direct request for the planted secret **failed**. The model refused.

The same secret came out when the request was reframed as roleplay.

Two attempts, one target, one refusal and one success. Mapped to OWASP
LLM08:2026 Hidden Context Exposure and MITRE ATLAS AML.T0057.

That gap is the entire lesson of this playbook. A control that holds against the
direct form of a request and fails against a costume version of the same request
is not a control. It is a filter on phrasing.

---

## Detect (DE)

**The hard part: extraction often looks like normal use.** A user asking "what
can you help with" and a user mapping your system prompt produce similar traffic.

**Signals, most to least reliable:**

1. **Known secret material appearing in output.** If a canary value is planted
   in the system prompt, match on it directly. This is the only high-confidence
   detection available and it requires deciding in advance to plant one.
2. **Sustained probing from one session.** Not one question, but a run of
   questions about the assistant's own instructions, capabilities, or
   restrictions. Rate and topic together, not either alone.
3. **Roleplay and hypothetical framing.** "Pretend you are", "in a story where",
   "for a security test". Weak on its own since legitimate users write like this,
   but meaningful when combined with signal 2.
4. **Output containing text that matches the system prompt.** Requires having
   the prompt available to compare against at detection time.

## Respond (RS)

1. **Establish what was actually disclosed.** Read the model output. Do not
   infer from the user's request. Asking for the system prompt and receiving it
   are different events and only one is an incident.
2. **If a credential was in the system prompt, treat it as compromised.** Not
   "possibly compromised". It was in a context window that produced output to an
   untrusted party. Rotate it.
3. **If another user's data was disclosed, this is a data incident**, and the
   notification obligations belong to legal and privacy, not to the responder.
4. **Preserve the exchange** before terminating anything.

## Recover (RC)

1. Rotate any credential that was in the exposed context.
2. Remove it from the system prompt. A secret in a prompt is a secret in a
   context window, reachable by anything that can influence generation.
3. If document content leaked across a user boundary, the retrieval layer's
   access control is the fault, not the model. Fix it there.

## Identify, Improvement (ID.IM)

**Ask specifically: was the direct form of this attack blocked while an indirect
form succeeded?** If so, the control is matching on phrasing, and its measured
effectiveness against the direct form is misleading.

This is testable. Take each refusal your system produces and try three rewrites
of the same request. My test found a refusal and a success for the same secret.

## Govern (GV) and Protect (PR), before the next one

- No secrets in system prompts. Ever. This removes the incident class rather
  than detecting it.
- Retrieval enforces per-user access control at the retrieval layer, so the model
  never holds text the user could not read directly.
- Plant a canary in the system prompt specifically so that extraction is
  detectable. It costs nothing and it is the only reliable signal here.

## What this playbook cannot tell you

Whether a partial disclosure occurred. A model can paraphrase its instructions
without reproducing them, and no string match catches that. The refusal in my
test was a genuine refusal. A paraphrase would have registered as one too.

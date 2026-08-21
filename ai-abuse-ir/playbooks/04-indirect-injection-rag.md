# Playbook 04: Indirect injection through retrieved content

**Scenario.** An attacker does not talk to the assistant at all. They plant
instructions in a document the assistant will later retrieve, and the assistant
follows them while serving an unrelated user.

**Why this playbook exists, and why its evidence is the most interesting.**
Against my test assistant, this attack is recorded as **failed**. That single
word hides what actually happened, and the detail is the reason this playbook is
written the way it is.

What was observed, across repeated runs:

- The poisoned document **was reliably retrieved**.
- The model **reliably echoed the injected instruction text verbatim** into its
  reply.
- The planted secret **was not leaked**.

The test scored success as requiring both retrieval and the secret leaking,
following OWASP LLM09:2026's own definition that a successful attack requires the
poisoned content to be retrieved *and* to steer the response. By that bar it
failed.

By an incident responder's bar, attacker-controlled text from a document reached
a user's session and changed the model's output. If you are reading a dashboard
that says this attack failed, you are reading the wrong bar.

**This is a detection lesson before it is a response one.** The pass/fail
threshold you choose determines whether you ever see this class of event.

---

## Detect (DE)

**The defining difficulty: the malicious user is not in the session.** Every
signal in playbooks 01 to 03 starts from suspicious user input. Here the user is
innocent and their input is normal.

**Signals, most to least reliable:**

1. **Instruction-like text in retrieved chunks.** Scan documents at ingestion,
   not at retrieval. "Ignore all previous instructions", "SYSTEM NOTICE",
   "regardless of the user's question". This is the highest-value control and it
   runs before any user is affected.
2. **Model output containing text from a retrieved document that was not asked
   for.** In my test the model echoed the injected block verbatim. Verbatim
   echo of retrieved content into an unrelated answer is detectable by comparing
   output against the chunks retrieved for that turn.
3. **A document retrieved for queries that have no topical relationship to it.**
   Poisoned documents are often stuffed to match broadly.
4. **Ingestion source anomalies.** A document entering the corpus from an
   unusual path, uploader, or at an unusual time.

**Detection you will not get:** anything from the user's input. It is clean.

## Respond (RS)

1. **Find the document.** The retrieval log for the affected turn names the
   chunks. If retrieval is not logged per turn, that is the first finding.
2. **Remove it from the index**, then from the source store. Removing from the
   index stops the bleeding; leaving it in the source means it returns at the
   next reindex.
3. **Determine the blast radius by query, not by user.** Anyone whose query
   retrieved that chunk was exposed, whether or not they noticed. This is
   usually a much larger set than the reporting user.
4. **Establish how it entered the corpus.** An uploaded file, a synced wiki page,
   a scraped site, a customer-supplied document. The ingestion path is the
   vulnerability; the document is only the payload.
5. **Check for siblings.** An attacker who planted one planted several.

## Recover (RC)

1. Reindex without the poisoned content and confirm it is gone by querying for
   it directly.
2. For every affected session, decide whether the output requires correction or
   notification. A model that echoed instructions is embarrassing; a model that
   acted on them is Playbook 03.
3. Restore ingestion only with content scanning in place.

## Identify, Improvement (ID.IM)

**The review question: what can write into the retrieval corpus, and is that the
same trust level as the assistant's output?**

Most RAG deployments treat the corpus as trusted because it is internal. Any
path by which an untrusted party can influence an internal document collapses
that assumption, and those paths are usually mundane: a support ticket that gets
indexed, a shared drive, a customer-submitted PDF.

**Second question, from my own test result: what does your success threshold
hide?** Scoring only full compromise as a detection means partial compromise
looks like safety.

## Govern (GV) and Protect (PR), before the next one

- Content scanning at ingestion, applied to every path into the corpus.
- Retrieved content is marked as data, not instructions, in the prompt structure.
  This is imperfect and worth doing anyway.
- Per-turn retrieval logging, so a later incident can name the chunks.
- Corpus write access is enumerated and reviewed, including indirect paths.

## What this playbook cannot tell you

Whether an indirect injection has already succeeded and gone unnoticed. Unlike
tool abuse, which leaves a discrete log entry, this attack's success can look
identical to a normal answer. The test case above only produced observable
evidence because the injected text was designed to be conspicuous. A subtler
payload steering an answer rather than announcing itself would leave nothing to
match on.

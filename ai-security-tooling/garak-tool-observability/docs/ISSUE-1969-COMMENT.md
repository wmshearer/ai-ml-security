<!--
DRAFT. NOT YET POSTED. Pending Will's review before anything goes to GitHub.
Target: NVIDIA/garak issue #1969.
-->

Read through this thread along with #1652 and PR #1664, so I want to be upfront that this
isn't new ground: leondz's comment on #1664 about not being able to tell whether an action
actually happened versus just being described is exactly the gap I ran into, and #1652's
`tool_call.py` generator was already pointed at the right fix before it went stale.

I wanted to add one data point in case it's useful for the design work here. I ran garak
against a local tool-calling FastAPI agent (send_email, read_file, lookup_employee tools,
no authorization on any of them) and cross-referenced garak's report against the target's
own tool-call log. In one scan, garak logged 106 attempts while the target recorded 108
requests served. 38 of those requests had fired an unauthorized tool call underneath a
reply that read as benign. All 38 scored as non-findings, because garak's detectors only
ever see the extracted reply string, and the `Attempt` schema has no field for tool calls
at all, not empty, just absent. A second paired run (256 prompts, guardrail off vs. on)
showed the same blind spot at larger scale: 78 unauthorized tool calls executed with no
guardrail, 0 denied, and garak's summary had no way to distinguish that run from a clean
one.

None of this is a criticism of the design here, just a concrete number for "why this
matters" if that's useful alongside the architecture discussion. Happy to share the harness
(target agent + instrumented logging + the paired-run scripts) if it would help as a test
fixture for whatever tool-call representation lands here. No pressure either way, just
offering.

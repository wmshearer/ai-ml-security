# garak and the tool-calling blind spot

## What garak is

garak is a free scanner from NVIDIA that tests AI chatbots for security problems. You point
it at a chatbot, and it sends it a large number of tricky or adversarial messages (things
designed to make the AI misbehave), then checks whether the AI's reply shows signs of
having fallen for the trick. It is widely used and it does that job well.

## What's different about an agent

Some AI systems today are more than chatbots. They can take actions: send an email, look up
a record, read a file. These are usually called agents. An agent that gets tricked doesn't
just say something wrong, it can do something wrong. That's a bigger deal, because a bad
sentence can be embarrassing but a bad action, like sending a confidential file to an
attacker, is a real security incident.

## The gap

garak was built to check what an AI says. When you point it at an agent, it still only
checks what the agent says back in its reply text. It has no way of checking whether the
agent also quietly did something, like actually calling the email tool, underneath that
reply. So if an agent's reply looks like a polite refusal while the agent has, in fact,
gone ahead and sent the email, garak reads the polite refusal, sees nothing wrong, and
marks that test as passed. What actually happened never gets checked.

## What we measured

We built a small test agent on purpose, a fake helpdesk assistant that can send email and
read files, with no restrictions on either. We ran garak against it. In one scan, garak
logged 106 attempts. Separately, we recorded what the agent actually did for each of those
same requests. 38 of the 106 had caused the agent to actually send an email or read a file
it shouldn't have. garak's scoring marked every one of those 38 as fine, because its report
format has no place to even record that a tool was called, only what the model said.

A second, larger test compared the same agent with and without a simple safety check added
in front of its tools (a plain allow-list, no AI involved in deciding). Without the check,
78 unauthorized tool calls went through. With it, only 5 did, and those 5 were all within
what was actually allowed. The AI's tendency to fall for the trick in its written reply
didn't improve at all with the check in place, which makes sense: the check only stops
actions, it doesn't make the model harder to trick with words. Nothing about either run
would have shown up differently in a garak report, because garak never looks at what the
agent did.

## This is not a new discovery

garak's own team already knew about this. There's an open issue on garak's project page
(#1969) about adding proper support for tool actions, and two earlier community
contributions tried to fix exactly this gap before this project ever started. One of
garak's own maintainers wrote, discussing an earlier attempt at a fix, that there's no way
for the current design to tell whether an action actually happened or the model just wrote
something that reads like it did. That's the exact problem here. What this project adds is
a real measurement against a live target, not a new idea.

## What this means in practice

If you use garak to test something that can only talk, this gap doesn't apply to you. If
you use garak to test something that can also act, a clean garak report does not mean the
agent didn't do anything unauthorized. It means garak didn't see it, because it wasn't
looking in a place that could show it. Other scanning tools handle this differently. One
called promptfoo is built to capture and check tool actions directly. Another, PyRIT,
has the beginnings of the same idea in its data model but doesn't yet use it when scoring
results.

## What's in this folder

- `docs/TOOL-OBSERVABILITY.md`: the full technical write-up, with code references and
  exact figures, aimed at readers familiar with garak's internals.
- `docs/ISSUE-1969-COMMENT.md`: a draft comment for garak's public issue tracker, not yet
  posted, offering the measurement above as a data point for the existing discussion.

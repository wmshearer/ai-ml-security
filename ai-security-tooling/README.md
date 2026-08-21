# AI supply chain audit

How much of the popular AI ecosystem ships in a format that runs code when you
load it.

No model file is downloaded. No pickle is opened. No package is installed. Every
number comes from public metadata.

## The result

**Weight formats across the 50 most-downloaded Hugging Face models:**

```
pickle only          9
both                19
safetensors only    20
neither              2
```

**28 of 50 (56%) ship at least one pickle-format weight file.** Nine offer no
safetensors alternative at all, so a user loading those models runs pickle or
does not use the model.

"Both" is its own category on purpose. It means the exposure is avoidable, not
removed: a caller whose library prefers safetensors is fine, and one that pins
the older filename still loads a pickle.

**OSV advisories for the common LLM stack:**

| Package | Advisories |
|---|---|
| transformers | 52 |
| langchain | 45 |
| llama-index | 31 |
| anthropic | 4 |
| chromadb | 2 |
| sentence-transformers | 0 |
| openai | 0 |

**None of them describes a malicious package.** All are vulnerabilities in
legitimate software, which is ordinary maintenance rather than a supply-chain
attack. Reporting one combined total would let the first masquerade as the
second.

## Why pickle matters

Python's pickle format is a small stack machine whose opcodes can import a module
and call it. Loading a pickle can therefore run code. PyTorch's traditional
`.bin` and `.pt` weights are pickle-based.

Safetensors exists to remove that: a header length, a JSON header of names,
dtypes and offsets, then raw tensor bytes. Nothing executable.

Hugging Face scans uploads and says of its own scanning that "this is not 100%
foolproof".

## What this measures, and what it refuses to

It measures **exposure**: how many models ship a format that executes on load.

It does not measure **malice**. That would need reading file contents, and the
scanners that do read them have published bypasses. JFrog documented a model
evading Hugging Face's scan using `runpy`. ReversingLabs documented a
7z-compressed pickle carrying a deliberately corrupted opcode placed so the
integrity check failed while Python still executed the payload first.

A safety score built from filenames would be less accurate than a scanner already
known to be evadable, while sounding more confident. Exposure is a number that
means exactly what it says.

## The bug the control caught

The malicious-package check originally looked for a `MAL-` identifier prefix.

Run against `ctx`, a package genuinely compromised on PyPI in 2022, it reported
zero. OSV returns three advisories for `ctx`, two titled "Malware in ctx" and
"Embedded Malicious Code in ctx", both with `GHSA-` identifiers because they came
through GitHub's advisory feed rather than OSV's malware feed.

So the audit would have called a known-compromised package clean, and its zero
for the AI stack would have been indistinguishable from a broken query.

The check now matches the identifier prefix or the advisory summary, and a
control test runs it against `ctx` on every network run. Without that control,
"zero malicious packages" is not a finding, it is an unverified claim.

## Running it

```
python3 src/audit.py              # live APIs, writes data/snapshot.json
python3 -m pytest tests/ -q       # offline
python3 -m pytest -m network      # includes the ctx control
```

Both APIs are public and need no account:

- `https://huggingface.co/api/models/{id}`
- `https://api.osv.dev/v1/query`

## Limits

- Metadata only. Nothing here inspects a file's contents.
- Advisory counts are historical and package-wide. A count is not current
  exposure, since a fixed vulnerability still appears in the total.
- The model sample is the 50 most downloaded, so it says nothing about the long
  tail, which is where published malicious models were actually found.
- A pickle-format file is not a malicious file. Almost all of them are ordinary
  model weights.

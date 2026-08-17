# AI Red Team Harness

**Phase 1 of an AI red-team harness project.** This phase builds the
foundation: a local LLM runtime, a deliberately vulnerable LLM-backed agent
as the test target, and proof that prompt-injection-class attacks succeed
against it. Later phases will extend [garak](https://github.com/NVIDIA/garak)
and [PyRIT](https://github.com/microsoft/PyRIT) against this (and other)
targets rather than reinventing their attack machinery — see
`/home/kali/director/projects/wshearer-site/research/phase-0-ai-redteam-harness.md`
for the build-vs-extend decision and full research basis.

## What's here (Phase 1)

- **A deliberately vulnerable "internal helpdesk assistant"** — a small
  FastAPI service backed by a locally-hosted Qwen2.5-7B-Instruct model
  (via Ollama), with a tiny RAG layer over synthetic internal documents,
  three callable tools, and a planted system-prompt secret. See
  `docs/target-design.md` for the full vulnerability catalog, each mapped to
  its OWASP Top 10 for LLM Applications (2026) category and MITRE ATLAS
  technique ID.
- **A small attack-proof script** (`tests/run_attacks.py`, *not* the full
  Phase 2 harness) demonstrating direct prompt injection, system-prompt/
  canary-secret extraction, indirect injection via a poisoned RAG document,
  and excessive-agency tool misuse — with real, captured model output as
  evidence in `evidence/attack_results.json`.

Everything runs fully local — no paid APIs, no cloud calls, no API keys.
All data (employee records, documents, the "secret") is synthetic, invented
for this project. No real names, credentials, or company data appear
anywhere in this repo.

## Requirements

- [Ollama](https://ollama.com) installed and running
  (`ollama serve`), with `qwen2.5:7b-instruct-q4_K_M` pulled
  (`ollama pull qwen2.5:7b-instruct-q4_K_M`, ~4.7GB download).
- Python 3.11+.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

## Run the target

```bash
source .venv/bin/activate
uvicorn src.target.main:app --host 127.0.0.1 --port 8000
```

Then, in another terminal:

```bash
curl -s -X POST http://127.0.0.1:8000/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "How do I reset my password?"}'
```

## Run the attack demonstration

With the target running (and Ollama serving the model):

```bash
source .venv/bin/activate
python tests/run_attacks.py
```

This prints each attack's payload, the model's actual raw output, and
whether it succeeded, then writes the full evidence to
`evidence/attack_results.json`.

## Project layout

```
src/target/          the vulnerable target agent
  main.py             FastAPI app, prompt construction, tool-call loop
  config.py           system prompt + canary secret
  rag.py              naive keyword-retrieval RAG layer
  tools.py            lookup_employee / send_email / read_file tool impls
  fake_data.py        synthetic employee records, fake filesystem
  docs_corpus/        7 synthetic internal docs, 1 deliberately poisoned
tests/run_attacks.py  Phase 1 attack proof script (not the Phase 2 harness)
docs/target-design.md full vulnerability writeup, OWASP/ATLAS mapping
evidence/             captured attack run output (JSON)
```

## License / attribution

MIT (this repo). Depends on Ollama (MIT) and Qwen2.5-7B-Instruct
(Apache-2.0). No jailbreak/harmful-content corpora are vendored — all attack
payloads in `tests/run_attacks.py` are self-authored, benign test strings.

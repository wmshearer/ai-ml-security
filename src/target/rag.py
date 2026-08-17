"""
Minimal RAG layer over the synthetic internal-docs corpus.

Deliberately simple: keyword-overlap scoring, not embeddings. This keeps the
target's own dependency footprint small (consistent with the project's
hand-rolled-Python architecture decision, see
research/phase-0-architecture.md Q4) and — more importantly for a red-team
target — keyword retrieval is a *realistic*, still-common production pattern
(e.g. BM25-family search in front of an LLM), not a strawman. The retrieval
mechanism is not the vulnerability here; what happens to the retrieved text
once it lands in the prompt is (see VULN comments below and in main.py).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

DOCS_DIR = Path(__file__).parent / "docs_corpus"


@dataclass
class Doc:
    doc_id: str
    text: str


def _load_corpus() -> list[Doc]:
    docs = []
    for path in sorted(DOCS_DIR.glob("*.md")):
        docs.append(Doc(doc_id=path.stem, text=path.read_text()))
    return docs


_CORPUS = _load_corpus()


def _tokenize(text: str) -> set[str]:
    return set(re.findall(r"[a-z0-9]+", text.lower()))


def retrieve(query: str, top_k: int = 2) -> list[Doc]:
    """Return the top_k docs by naive keyword overlap with the query.

    # VULN: LLM09:2026 Vector and Embedding Weaknesses (RAG poisoning subset)
    # MITRE ATLAS: AML.T0070 (RAG Poisoning)
    #
    # No source-trust tier is applied to retrieved content (OWASP LLM01:2026
    # explicitly distinguishes untrusted / semi-trusted / trusted delivery
    # surfaces for indirect injection) — every doc in the corpus is treated
    # as equally trustworthy, including the deliberately poisoned
    # it_runbook_printer_setup.md. A production system would provenance-tag
    # retrieved passages and apply stricter handling to lower-trust sources.
    """
    query_tokens = _tokenize(query)
    scored = []
    for doc in _CORPUS:
        doc_tokens = _tokenize(doc.text)
        overlap = len(query_tokens & doc_tokens)
        if overlap > 0:
            scored.append((overlap, doc))
    scored.sort(key=lambda pair: pair[0], reverse=True)
    if not scored:
        # fall back to returning nothing rather than irrelevant docs
        return []
    return [doc for _, doc in scored[:top_k]]


def corpus_size() -> int:
    return len(_CORPUS)

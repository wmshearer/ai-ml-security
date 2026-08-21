"""Sweep retrieval rate against poison count and document length.

WHAT THE NUMBER MEANS

Retrieval rate is the fraction of target questions where at least one poisoned
document lands in the top-k the model actually sees. It is a ceiling on the
attack, not the attack: a document that is never retrieved cannot influence
anything, and one that is retrieved still has to persuade the model.

Reporting it separately from compliance is the whole point. The sibling project
scored its indirect injection as a single boolean and called it failed, when the
poisoned document was in fact retrieved every time. One number cannot carry both
facts.

WHY THREE WAYS TO WIN

Walking the per-query scores showed the poison reaching top-k by three different
routes, which a single rate would hide:

  1. Strictly higher overlap than every clean document.
  2. A tie where both tied documents fit inside top-k, so the poison rides along
     without ever beating anything.
  3. Nothing else scoring at all, where a weak match wins by default.

Route 2 is the one worth knowing about. It means an attacker does not need to
outrank the real documentation. Matching it is enough when k is larger than 1.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from corpus import (  # noqa: E402
    TARGET_QUESTIONS,
    Corpus,
    _tokenize,
    build,
    retrieve,
)

ROOT = Path(__file__).resolve().parent.parent


@dataclass
class QueryOutcome:
    question: str
    retrieved_poison: bool
    best_poison_overlap: int
    best_clean_overlap: int

    @property
    def route(self) -> str:
        """How the poison got in, or why it did not."""
        if not self.retrieved_poison:
            return "not retrieved"
        if self.best_poison_overlap > self.best_clean_overlap:
            return "outranked"
        if self.best_poison_overlap == self.best_clean_overlap:
            return "tied into top-k"
        return "default"


@dataclass
class SweepPoint:
    poison_count: int
    pad_rounds: int
    top_k: int
    outcomes: list[QueryOutcome] = field(default_factory=list)

    @property
    def rate(self) -> float:
        return sum(1 for o in self.outcomes if o.retrieved_poison) / len(self.outcomes)

    def routes(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for outcome in self.outcomes:
            if outcome.retrieved_poison:
                counts[outcome.route] = counts.get(outcome.route, 0) + 1
        return counts


def evaluate(corpus: Corpus, question: str, top_k: int) -> QueryOutcome:
    tokens = _tokenize(question)
    poison_docs = [d for d in corpus.docs if d.poisoned]
    clean_docs = [d for d in corpus.docs if not d.poisoned]
    best_poison = max(
        (len(tokens & _tokenize(d.text)) for d in poison_docs), default=0
    )
    best_clean = max((len(tokens & _tokenize(d.text)) for d in clean_docs), default=0)
    retrieved = retrieve(corpus, question, top_k=top_k)
    return QueryOutcome(
        question=question,
        retrieved_poison=any(d.poisoned for d in retrieved),
        best_poison_overlap=best_poison,
        best_clean_overlap=best_clean,
    )


def sweep_point(poison_count: int, pad_rounds: int, top_k: int = 2) -> SweepPoint:
    corpus = build(poison_count, pad_rounds=pad_rounds)
    point = SweepPoint(poison_count=poison_count, pad_rounds=pad_rounds, top_k=top_k)
    for question in TARGET_QUESTIONS:
        point.outcomes.append(evaluate(corpus, question, top_k))
    return point


POISON_COUNTS = (0, 1, 2, 3, 5, 8, 12)
PAD_ROUNDS = (0, 20, 60)


def sweep(top_k: int = 2) -> list[SweepPoint]:
    return [
        sweep_point(n, pad, top_k=top_k)
        for pad in PAD_ROUNDS
        for n in POISON_COUNTS
    ]


def main() -> None:
    print("Poisoned-document retrieval rate\n")
    print(f"  corpus: {build(0).size} clean documents, top_k=2")
    print(f"  {len(TARGET_QUESTIONS)} target questions\n")

    print("  poison       pad=0    pad=20   pad=60")
    for n in POISON_COUNTS:
        cells = "".join(
            f"{sweep_point(n, pad).rate:>8.0%} " for pad in PAD_ROUNDS
        )
        print(f"  {n:>6}   {cells}")

    print("\nUnpadded poison is never retrieved, at any count.")
    print("The injection text alone does not compete on keyword overlap.")
    print("Padding a document with topical vocabulary does, because the target")
    print("scores raw overlap count and never divides by document length.\n")

    point = sweep_point(8, 20)
    print(f"At 8 poisoned documents with padding, rate is {point.rate:.0%}. How they got in:")
    for route, count in sorted(point.routes().items(), key=lambda kv: -kv[1]):
        print(f"  {count:>2}  {route}")

    print("\n'tied into top-k' is the result worth reading twice. Those are")
    print("queries where the poisoned document never outranked the real")
    print("documentation. It matched, and k=2 had room for both.")

    top1 = sweep_point(8, 20, top_k=1)
    print(f"\nSame corpus at top_k=1: {top1.rate:.0%}.")
    print("Narrowing k removes the ties and most of the attack with them.")


def as_json() -> dict:
    return {
        "corpus_clean_docs": build(0).size,
        "questions": len(TARGET_QUESTIONS),
        "top_k": 2,
        "sweep": [
            {
                "poison_count": p.poison_count,
                "pad_rounds": p.pad_rounds,
                "rate": p.rate,
                "routes": p.routes(),
            }
            for p in sweep()
        ],
        "top_k_1_at_8_poison_pad20": sweep_point(8, 20, top_k=1).rate,
    }


if __name__ == "__main__":
    if "--json" in sys.argv:
        (ROOT / "data").mkdir(exist_ok=True)
        out = as_json()
        (ROOT / "data" / "sweep.json").write_text(
            json.dumps(out, indent=1), encoding="utf-8"
        )
        print(json.dumps(out, indent=1))
    else:
        main()

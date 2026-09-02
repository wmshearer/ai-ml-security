"""Summarize the attack evidence the playbooks are built on.

Reads the real recorded evidence from the sibling ai-redteam-harness project
(evidence/attack_results.json) and prints one line per attack: whether it
succeeded, and the OWASP category it maps to. This is the same evidence file
tests/test_sourcing.py reads from directly.

Usage: python3 scripts/summarize_evidence.py
"""

from __future__ import annotations

import json
from pathlib import Path

EVIDENCE_PATH = Path(
    "/home/kali/director/projects/ai-redteam-harness/evidence/attack_results.json"
)


def main() -> None:
    results = json.loads(EVIDENCE_PATH.read_text())

    print("Attack results the playbooks are built on:")
    print()
    for r in results:
        status = "SUCCEEDED" if r["succeeded"] else "failed"
        print(f"  {status:<10}{r['attack']}")
        print(f"  {'':<10}{r['owasp']}")

    succeeded = sum(1 for r in results if r["succeeded"])
    print()
    print(f"{succeeded} of {len(results)} succeeded. The two failures are cited too.")


if __name__ == "__main__":
    main()

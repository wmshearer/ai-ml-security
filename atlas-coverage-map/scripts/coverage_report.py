#!/usr/bin/env python3
"""Print the ATLAS coverage map: three LLM-misuse data sources against ATLAS v2026.07."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src import atlas  # noqa: E402
from src import coverage  # noqa: E402

BAR_WIDTH = 20


def bar(fraction: float) -> str:
    filled = round(fraction * BAR_WIDTH)
    return "#" * filled + "." * (BAR_WIDTH - filled)


def main() -> None:
    print("MITRE ATLAS coverage map: three data sources against ATLAS v2026.07")
    print("(16 tactics, 101 top-level techniques)\n")

    by_source = coverage.covered_techniques()
    sources_by_technique: dict[str, list[str]] = {}
    for source, ids in by_source.items():
        for tid in ids:
            sources_by_technique.setdefault(tid, []).append(source)

    print("=== Covered techniques ===")
    for tid in sorted(sources_by_technique):
        sources = ", ".join(sorted(sources_by_technique[tid]))
        print("  %-12s %-32s [%s]" % (tid, atlas.technique_name(tid), sources))

    tc = coverage.technique_coverage()
    print("\n=== Technique-level coverage ===")
    print("  %d of %d (%.1f%%)" % (tc["covered"], tc["total"], tc["fraction"] * 100))

    print("\n=== Tactic-level coverage ===")
    tacs = coverage.tactic_coverage()
    touched = coverage.tactics_touched()
    for tac_id in atlas.tactic_order():
        info = tacs[tac_id]
        mark = "touched" if tac_id in touched else "  --   "
        print("  %-22s %2d/%-3d [%s] %s" % (
            info["name"], info["covered"], info["total"], bar(info["fraction"]), mark,
        ))
    print("\n  %d of 16 tactics touched, %d untouched" % (len(touched), 16 - len(touched)))

    print("\n=== Notable gaps: untouched tactics ===")
    g = coverage.gaps()
    untouched = [tac_id for tac_id in atlas.tactic_order() if tac_id not in touched]
    for tac_id in untouched:
        uncovered = g[tac_id]
        print("  %s (%d uncovered techniques)" % (atlas.tactic_name(tac_id), len(uncovered)))
        for tid, name in uncovered[:3]:
            print("    %-12s %s" % (tid, name))
        if len(uncovered) > 3:
            print("    ... and %d more" % (len(uncovered) - 3))

    print()
    print("This is coverage of three specific data sources (ai-threat-intel-analysis,")
    print("jailbreak-corpus-analysis, llm-abuse-detection) against the ATLAS matrix, not")
    print("a claim of complete AI-threat coverage. A gap means the technique is not")
    print("present in this data, not that it cannot happen.")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Summarise the documented AI-misuse cases and the 2024 to 2025 shift."""
from __future__ import annotations
import json, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from data.cases import CASES, INTEGRATION_LEVELS  # noqa: E402
from src.analyze import (  # noqa: E402
    ATLAS, atlas_coverage, actors_by_sponsor, integration_by_period,
    atlas_techniques, owasp_categories, first_appearance,
)

print("Documented AI-misuse cases from public threat reports: %d\n" % len(CASES))

print("=== Actors by attributed sponsor ===")
for sponsor, n in actors_by_sponsor().most_common():
    print("  %-14s %d" % (sponsor, n))

print("\n=== How AI was integrated, by period ===")
periods = sorted(integration_by_period())
print("  %-9s %6s %8s %8s" % ("PERIOD", "aid", "runtime", "agentic"))
for p in periods:
    c = integration_by_period()[p]
    print("  %-9s %6d %8d %8d" % (p, c["aid"], c["runtime"], c["agentic"]))
for level in INTEGRATION_LEVELS:
    fa = first_appearance(level)
    print("  first '%s': %s" % (level, fa or "not observed"))

print("\n=== MITRE ATLAS technique coverage ===")
for tid, n in atlas_coverage().most_common():
    print("  %-12s %-40s %d" % (tid, ATLAS[tid], n))

rows = []
for c in CASES:
    rows.append({
        "actor": c.actor, "sponsor": c.sponsor, "period": c.period,
        "integration": c.integration, "source": c.source,
        "atlas": sorted(atlas_techniques(c)), "owasp": sorted(owasp_categories(c)),
    })
out = ROOT / "reports" / "case-mapping.json"
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(json.dumps({"cases": rows}, indent=2))
print("\nwrote %s" % out)
print()
print("Every case comes from a named public report. This organises and measures what")
print("those reports document. It is not new intelligence.")

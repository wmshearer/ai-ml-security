#!/usr/bin/env python3
"""Print a summary of the jailbreak corpus: type/pattern/platform counts and framework
coverage. Prints counts and classifications only, never prompt text, so the output
stays safe to paste or screenshot anywhere.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from data.corpus import load_corpus  # noqa: E402
from src.analyze import (  # noqa: E402
    ATLAS,
    OWASP_2025,
    PATTERNS,
    atlas_for_pattern,
    owasp_for_pattern,
    pattern_distribution,
    platform_distribution,
    type_distribution,
    unclassified_count,
)

corpus = load_corpus()

print("Jailbreak corpus analysis: verazuo/jailbreak_llms (MIT), 1,405 prompts, CCS 2024")
print("=" * 80)
print()
print("Total prompts: %d" % len(corpus))

print()
print("=== Type distribution (Liu et al.'s 3 types; a prompt may count in more than one) ===")
for type_name, n in type_distribution(corpus).most_common():
    print("  %-22s %5d" % (type_name, n))

print()
print("=== Pattern distribution (Liu et al.'s 10 patterns, reconstructed classifier) ===")
for pattern_name, n in pattern_distribution(corpus).most_common():
    print("  %-24s %5d" % (pattern_name, n))

print()
print("=== Platform distribution ===")
for platform, n in platform_distribution(corpus).most_common():
    print("  %-12s %5d" % (platform, n))

print()
uc = unclassified_count(corpus)
print("=== Unclassified ===")
print("  %d prompts (%.1f%%) matched no pattern" % (uc, 100 * uc / len(corpus)))

print()
print("=== ATLAS / OWASP coverage by pattern ===")
print("  %-24s %-14s %s" % ("PATTERN", "ATLAS", "OWASP"))
for pattern_name in PATTERNS:
    atlas_ids = ", ".join(sorted(atlas_for_pattern(pattern_name)))
    owasp_ids = ", ".join(sorted(owasp_for_pattern(pattern_name)))
    print("  %-24s %-14s %s" % (pattern_name, atlas_ids, owasp_ids))

print()
print("=== Framework reference ===")
for tid, name in ATLAS.items():
    print("  %-12s %s" % (tid, name))
for oid, name in OWASP_2025.items():
    print("  %-6s %s" % (oid, name))

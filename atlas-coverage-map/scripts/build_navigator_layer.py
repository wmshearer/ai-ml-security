#!/usr/bin/env python3
"""Build an ATLAS Navigator layer json from the computed coverage.

The MITRE ATLAS Navigator (mitre-atlas.github.io/atlas-navigator, the ATT&CK Navigator
fork for ATLAS) reads a layer file that scores each technique id. This writes
data/navigator_layer.json in that format: covered techniques get score 1 (rendered
green by the gradient below) and a comment naming which of the three sources covers
them. Techniques not in the covered set are left out of the techniques list, which the
Navigator renders as unscored.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src import atlas  # noqa: E402
from src import coverage  # noqa: E402

OUT = ROOT / "data" / "navigator_layer.json"


def build_layer() -> dict:
    by_source = coverage.covered_techniques()

    sources_by_technique: dict[str, list[str]] = {}
    for source, ids in by_source.items():
        for tid in ids:
            sources_by_technique.setdefault(tid, []).append(source)

    techniques = []
    for tid in sorted(sources_by_technique):
        sources = sorted(sources_by_technique[tid])
        techniques.append({
            "techniqueID": tid,
            "score": 1,
            "color": "",
            "comment": "covered by: " + ", ".join(sources),
            "enabled": True,
        })

    cov = coverage.technique_coverage()
    return {
        "name": "ATLAS coverage map: three LLM-misuse data sources",
        "versions": {
            "attack": "17",
            "navigator": "5.1.0",
            "layer": "4.5",
        },
        "domain": "mitre-atlas",
        "description": (
            "Coverage of %d of %d ATLAS v2026.07 top-level techniques (%.1f%%) by three "
            "sibling projects: ai-threat-intel-analysis, jailbreak-corpus-analysis, "
            "llm-abuse-detection. A gap means not present in this data, not impossible."
            % (cov["covered"], cov["total"], cov["fraction"] * 100)
        ),
        "filters": {"platforms": ["AI"]},
        "sorting": 0,
        "layout": {"layout": "side", "showID": True, "showName": True},
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {
            "colors": ["#ffffff", "#66b32e"],
            "minValue": 0,
            "maxValue": 1,
        },
        "legendItems": [
            {"label": "covered by at least one source", "color": "#66b32e"},
        ],
        "metadata": [
            {"name": "generated_by", "value": "scripts/build_navigator_layer.py"},
            {"name": "atlas_version", "value": atlas.load_atlas()["version"]},
        ],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
    }


def main() -> None:
    layer = build_layer()
    OUT.write_text(json.dumps(layer, indent=2))
    print("wrote %s (%d techniques scored)" % (OUT, len(layer["techniques"])))


if __name__ == "__main__":
    main()

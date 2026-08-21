"""Build a static ground-truth snapshot from cloud-detection-coverage.

This script READS the cloud-detection-coverage project (its STIX bundle, its
Sigma rule corpus, its coverage.py logic) and writes a JSON snapshot into this
project's own data/ directory. It does not modify anything under
projects/cloud-detection-coverage/.

The snapshot is what src/tools.py serves to the agent, and what src/score.py
checks the agent's answers against. Both read the same frozen file so a
number in FINDINGS.md can always be traced back to this one script's output.

Run:
    python3 src/build_ground_truth.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
SOURCE_PROJECT = HERE.parent / "cloud-detection-coverage"
OUT = HERE / "data" / "ground_truth.json"

sys.path.insert(0, str(SOURCE_PROJECT / "src"))


def main() -> None:
    import coverage  # the source project's own module, imported read-only

    result = coverage.analyse()
    techniques = result["techniques"]

    # Per-technique rule detail: which rule files claim it, and (for coverage
    # via a sub-technique) whether the claim is direct or via a child.
    rules_by_technique: dict[str, list[dict]] = {}
    cloud_root = SOURCE_PROJECT / "data" / "sigma"
    ruleset = coverage.RuleSet("rules/cloud", cloud_root / "rules" / "cloud").load()

    for path, tags, title in ruleset.rules:
        rel = str(path.relative_to(cloud_root))
        for tag in tags:
            rules_by_technique.setdefault(tag, []).append(
                {"rule_id": rel, "title": title, "tag_exact": tag}
            )
        # credit the parent technique too (mirrors coverage.py's expansion)
        for tag in tags:
            parent = coverage.parent_of(tag)
            if parent != tag:
                rules_by_technique.setdefault(parent, []).append(
                    {"rule_id": rel, "title": title, "tag_exact": tag, "via_subtechnique": True}
                )

    technique_out = {}
    for tid, tech in techniques.items():
        technique_out[tid] = {
            "id": tech.id,
            "name": tech.name,
            "platforms": sorted(tech.platforms),
            "is_subtechnique": tech.is_subtechnique,
            "tactics": tech.tactics,
            "covered": tid in result["covered"],
            "rule_count": len(rules_by_technique.get(tid, [])),
            "rules": rules_by_technique.get(tid, []),
        }

    snapshot = {
        "source_project": "cloud-detection-coverage",
        "attack_version": result["attack_version"],
        "cloud_platforms": sorted(coverage.CLOUD_PLATFORMS),
        "cloud_techniques_total": result["cloud_techniques"],
        "rules_total": result["rules"],
        "covered": result["covered"],
        "uncovered": result["uncovered"],
        "off_matrix": result["off_matrix"],
        "untagged_rules": result["untagged_rules"],
        "rules_per_technique": dict(result["rules_per_technique"]),
        "techniques": technique_out,
    }

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(snapshot, indent=2, sort_keys=True))
    print(f"Wrote {OUT}")
    print(f"  {snapshot['cloud_techniques_total']} cloud techniques, "
          f"{len(snapshot['covered'])} covered, {len(snapshot['uncovered'])} uncovered")
    print(f"  {snapshot['rules_total']} rules total")


if __name__ == "__main__":
    main()

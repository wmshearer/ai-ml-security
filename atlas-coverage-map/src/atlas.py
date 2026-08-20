"""Load and query the MITRE ATLAS matrix.

ATLAS (Adversarial Threat Landscape for Artificial-Intelligence Systems) is MITRE's
kill-chain matrix for attacks on AI systems, the ATT&CK equivalent for AI. It organises
adversary behaviour into tactics (the "why", the stage of the attack) and techniques (the
"how", the specific method). This module reads a flattened copy of ATLAS v2026.07
(data/atlas.json, built from the upstream YAML release at setup time so runtime code
touches only the standard library) and exposes small lookups over it.

Source: MITRE ATLAS, github.com/mitre-atlas/atlas-data, Apache License 2.0. See
data/ATLAS-APACHE-2.0-LICENSE.txt.

WHAT THIS IS NOT
    Not a copy of the ATLAS website or the full technique descriptions. It is the id,
    name, and tactic membership for each technique, which is all the coverage
    computation in src/coverage.py needs.
"""

from __future__ import annotations

import json
from pathlib import Path

DEFAULT = Path(__file__).resolve().parents[1] / "data" / "atlas.json"


def load_atlas(path: Path = DEFAULT) -> dict:
    """Read the flattened ATLAS matrix from json. No parsing beyond json.load."""
    with open(path) as f:
        return json.load(f)


_ATLAS = load_atlas()


def all_tactics() -> dict:
    """tactic id -> tactic name, all 16."""
    return _ATLAS["tactics"]


def tactic_order() -> list:
    """The 16 tactic ids in kill-chain order, as ATLAS orders them."""
    return _ATLAS["tactic_order"]


def tactic_name(tactic_id: str) -> str:
    return _ATLAS["tactics"][tactic_id]


def technique_name(technique_id: str) -> str:
    return _ATLAS["techniques"][technique_id]


def tactics_of(technique_id: str) -> list:
    """The tactic ids a technique belongs to. Some techniques belong to more than one,
    for example LLM Jailbreak sits under both Privilege Escalation and Defense Evasion."""
    return _ATLAS["technique_tactics"].get(technique_id, [])


def toplevel_techniques() -> list:
    """The 101 top-level technique ids (subtechniques excluded)."""
    return _ATLAS["toplevel_techniques"]

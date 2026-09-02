"""Read-only tools the agent can call.

Every tool here is a plain Python function plus a JSON schema (OpenAI/Ollama
function-calling format). All of them read from a single frozen snapshot,
data/ground_truth.json, built by build_ground_truth.py from the
cloud-detection-coverage project. Nothing here writes anything, shells out,
or touches the network. The tool surface itself is the security boundary:
there is no path from a tool call to a write, a shell command, or an outbound
request, regardless of what the model asks for.

Argument validation lives here, not in the prompt. A model calling a tool
with a malformed technique ID or a nonexistent rule ID gets a structured
error result back, not a crash and not a silent guess.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Callable

HERE = Path(__file__).resolve().parent.parent
GROUND_TRUTH = HERE / "data" / "ground_truth.json"
SIGMA_ROOT = HERE.parent / "cloud-detection-coverage" / "data" / "sigma"

_DATA: dict[str, Any] | None = None

TECH_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$", re.IGNORECASE)


def _data() -> dict[str, Any]:
    global _DATA
    if _DATA is None:
        if not GROUND_TRUTH.exists():
            raise FileNotFoundError(
                f"{GROUND_TRUTH} missing. Run build_ground_truth.py first."
            )
        _DATA = json.loads(GROUND_TRUTH.read_text())
    return _DATA


class ToolError(Exception):
    """A validation or lookup failure, returned to the model as a result,
    never raised up through the agent loop as a crash."""


def _normalise_technique_id(raw: str) -> str:
    if not isinstance(raw, str) or not raw.strip():
        raise ToolError("technique_id must be a non-empty string")
    candidate = raw.strip().upper()
    if not candidate.startswith("T"):
        candidate = "T" + candidate
    if not TECH_ID_RE.match(candidate):
        raise ToolError(
            f"'{raw}' is not a valid ATT&CK technique id. "
            "Expected format like T1078 or T1078.004."
        )
    return candidate


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------

def get_technique(technique_id: str) -> dict:
    """Look up an ATT&CK technique's name, tactics, platforms, and whether
    it is in the cloud technique set at all."""
    tid = _normalise_technique_id(technique_id)
    techs = _data()["techniques"]
    if tid not in techs:
        return {
            "found": False,
            "technique_id": tid,
            "note": (
                f"{tid} is not in the 152-technique cloud set for ATT&CK "
                f"v{_data()['attack_version']}. It may not exist, may not touch "
                "a cloud platform, or may be deprecated/revoked."
            ),
        }
    t = techs[tid]
    return {
        "found": True,
        "technique_id": t["id"],
        "name": t["name"],
        "tactics": t["tactics"],
        "platforms": t["platforms"],
        "is_subtechnique": t["is_subtechnique"],
    }


def list_rules_for_technique(technique_id: str) -> dict:
    """List the Sigma rules whose tags claim this technique (directly or via
    a child sub-technique). Empty list means no rule in the corpus tags it,
    which is the authoritative signal for 'uncovered', not a guess."""
    tid = _normalise_technique_id(technique_id)
    techs = _data()["techniques"]
    if tid not in techs:
        return {
            "technique_id": tid,
            "found_technique": False,
            "rules": [],
            "note": f"{tid} is not in the cloud technique set; cannot check coverage.",
        }
    t = techs[tid]
    return {
        "technique_id": tid,
        "found_technique": True,
        "covered": t["covered"],
        "rule_count": t["rule_count"],
        "rules": [
            {"rule_id": r["rule_id"], "title": r["title"], "tag_exact": r["tag_exact"]}
            for r in t["rules"]
        ],
    }


def search_rules(query: str) -> dict:
    """Case-insensitive keyword search over rule titles and descriptions in
    the cloud rule corpus. This is a text search only: a hit means the words
    appear in the rule file, not that the rule is tagged for any particular
    technique. Returns at most 15 matches."""
    if not isinstance(query, str) or not query.strip():
        raise ToolError("query must be a non-empty string")
    q = query.strip().lower()
    if not SIGMA_ROOT.exists():
        raise ToolError(f"rule corpus not found at {SIGMA_ROOT}")

    matches = []
    for path in sorted((SIGMA_ROOT / "rules" / "cloud").rglob("*.yml")):
        text = path.read_text(encoding="utf-8", errors="replace")
        if q in text.lower():
            title = ""
            for line in text.splitlines():
                if line.startswith("title:"):
                    title = line.split(":", 1)[1].strip()
                    break
            matches.append({
                "rule_id": str(path.relative_to(SIGMA_ROOT)),
                "title": title,
            })
            if len(matches) >= 15:
                break
    return {"query": query, "match_count": len(matches), "matches": matches}


def read_rule(rule_id: str) -> dict:
    """Read a Sigma rule's full YAML: title, tags, logsource, detection logic.
    rule_id is the path relative to the sigma repo root, e.g.
    'rules/cloud/aws/cloudtrail/aws_delete_identity.yml' (as returned by
    list_rules_for_technique or search_rules)."""
    if not isinstance(rule_id, str) or not rule_id.strip():
        raise ToolError("rule_id must be a non-empty string")
    rule_id = rule_id.strip()

    candidate = (SIGMA_ROOT / rule_id).resolve()
    # Enforce containment: the resolved path must stay inside SIGMA_ROOT.
    # This blocks path traversal (e.g. "../../../etc/passwd") regardless of
    # what the model passes; it is not a prompt-level restriction.
    try:
        candidate.relative_to(SIGMA_ROOT.resolve())
    except ValueError:
        raise ToolError(f"rule_id '{rule_id}' resolves outside the rule corpus; refused.")

    if not candidate.exists() or candidate.suffix != ".yml":
        return {
            "found": False,
            "rule_id": rule_id,
            "note": "No rule file at this path. Use search_rules or "
                    "list_rules_for_technique to find a valid rule_id first.",
        }
    return {
        "found": True,
        "rule_id": rule_id,
        "content": candidate.read_text(encoding="utf-8", errors="replace"),
    }


def check_logsource(rule_id: str) -> dict:
    """Extract just the logsource block (product/service/category) from a
    rule, i.e. what telemetry the rule needs in order to fire at all."""
    result = read_rule(rule_id)
    if not result["found"]:
        return result
    logsource: dict[str, str] = {}
    in_block = False
    for line in result["content"].splitlines():
        if line.startswith("logsource:"):
            in_block = True
            continue
        if in_block:
            if line.startswith((" ", "\t")):
                stripped = line.strip()
                if ":" in stripped:
                    k, v = stripped.split(":", 1)
                    logsource[k.strip()] = v.strip()
            else:
                break
    return {"found": True, "rule_id": rule_id, "logsource": logsource}


# ---------------------------------------------------------------------------
# Registry: name -> (callable, JSON schema)
# ---------------------------------------------------------------------------

TOOLS: dict[str, Callable[..., dict]] = {
    "get_technique": get_technique,
    "list_rules_for_technique": list_rules_for_technique,
    "search_rules": search_rules,
    "read_rule": read_rule,
    "check_logsource": check_logsource,
}

TOOL_SCHEMAS: list[dict] = [
    {
        "type": "function",
        "function": {
            "name": "get_technique",
            "description": (
                "Look up an ATT&CK technique by id. Returns its name, tactics, "
                "platforms, and whether it is in the 152-technique cloud set. "
                "Use this first to confirm a technique id is real before "
                "investigating its coverage."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "technique_id": {
                        "type": "string",
                        "description": "ATT&CK technique id, e.g. T1078 or T1078.004",
                    }
                },
                "required": ["technique_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_rules_for_technique",
            "description": (
                "List every Sigma rule tagged with this technique id (directly "
                "or via a child sub-technique). This is the authoritative "
                "coverage check: an empty list means no rule in the corpus "
                "claims this technique."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "technique_id": {
                        "type": "string",
                        "description": "ATT&CK technique id, e.g. T1078 or T1078.004",
                    }
                },
                "required": ["technique_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_rules",
            "description": (
                "Keyword search over rule titles and descriptions in the cloud "
                "rule corpus. A match means the words appear in the rule file, "
                "NOT that the rule is tagged for a particular technique. Use "
                "list_rules_for_technique for the authoritative tag-based check; "
                "use this to find candidate rules by topic or to check whether "
                "a rule 'about' something exists even if untagged."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "keyword or short phrase to search for",
                    }
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_rule",
            "description": (
                "Read a Sigma rule's full YAML (title, tags, logsource, "
                "detection logic). rule_id is the relative path returned by "
                "list_rules_for_technique or search_rules, e.g. "
                "'rules/cloud/aws/cloudtrail/aws_delete_identity.yml'."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "rule_id": {
                        "type": "string",
                        "description": "relative rule path, e.g. rules/cloud/aws/cloudtrail/aws_delete_identity.yml",
                    }
                },
                "required": ["rule_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "check_logsource",
            "description": (
                "Get just the logsource (product/service/category) a rule "
                "needs in order to fire, i.e. what telemetry has to be present."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "rule_id": {
                        "type": "string",
                        "description": "relative rule path, e.g. rules/cloud/aws/cloudtrail/aws_delete_identity.yml",
                    }
                },
                "required": ["rule_id"],
            },
        },
    },
]


def call_tool(name: str, arguments: dict) -> dict:
    """Dispatch a tool call by name. Never raises: unknown tools and bad
    arguments both come back as a structured error dict so the agent loop
    can record them as events and feed them back to the model."""
    if name not in TOOLS:
        return {
            "error": "unknown_tool",
            "message": f"'{name}' is not a valid tool. Valid tools: {sorted(TOOLS)}",
        }
    func = TOOLS[name]
    if not isinstance(arguments, dict):
        return {"error": "bad_arguments", "message": "arguments must be a JSON object"}
    try:
        return func(**arguments)
    except ToolError as e:
        return {"error": "invalid_argument", "message": str(e)}
    except TypeError as e:
        return {"error": "bad_arguments", "message": str(e)}
    except Exception as e:  # noqa: BLE001 - tool must never crash the loop
        return {"error": "tool_exception", "message": f"{type(e).__name__}: {e}"}

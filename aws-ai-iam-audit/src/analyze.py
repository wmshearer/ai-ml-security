#!/usr/bin/env python3
"""
Custom structural analysis of AWS managed IAM policies for AI services.

Generic IAM linters (cloudsplaining, parliament) flag broad categories: "uses
Resource *", "allows service:*", "no resource constraint". They do not know
which of those wildcards matter for a specific attack path. This script looks
for three specific structural patterns across the fetched policy corpus:

  1. PASSROLE_WILDCARD
     An iam:PassRole statement whose Resource includes "*" or "arn:*:iam::*:role/*"
     (i.e. any role in the account, not scoped to specific role name patterns).

  2. TAG_GATED_CONDITION
     A statement whose Condition depends on a resource/request tag value
     (aws:ResourceTag/*, aws:RequestTag/*, s3:ExistingObjectTag/*, etc.) where
     the tag key or required value is something a principal with tagging
     permissions on their own resources could set themselves. This does not
     mean the condition is useless -- it means the security boundary rests on
     a value the tagged principal controls, not on an AWS-controlled fact.

  3. WILDCARD_RESOURCE_GRANT
     Any Allow statement whose Resource is exactly "*" (not scoped to a
     service or resource type at all).

  4. ANY_BUCKET_RESOURCE
     Any Allow statement whose Resource is an S3 ARN pattern that matches
     every bucket in every account, i.e. "arn:aws:s3:::*" or
     "arn:aws:s3:::*/*", as distinct from a global "*" Resource. This is
     usually combined with a tag condition (see TAG_GATED_CONDITION above)
     that is meant to narrow it back down -- worth checking whether that tag
     is one only AWS can set, or one any principal with tagging rights on
     their own object can set.

The output is deliberately literal: statement IDs (Sid) and policy names are
named directly so every count in the README can be traced back to one exact
statement in one exact fetched JSON file.
"""

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
POLICIES_DIR = REPO_ROOT / "policies"
EVIDENCE_DIR = REPO_ROOT / "evidence"

# Condition key prefixes that represent values a principal can set on their
# own resources (tags), as opposed to values AWS itself asserts (e.g.
# aws:SourceArn, aws:PrincipalOrgID, aws:CalledViaLast).
ATTACKER_SETTABLE_CONDITION_PREFIXES = (
    "aws:ResourceTag/",
    "aws:RequestTag/",
    "s3:ExistingObjectTag/",
    "s3:RequestObjectTag/",
    "sagemaker:ResourceTag/",
    "iam:ResourceTag/",
)

PASSROLE_WILDCARD_RESOURCES = {"*", "arn:aws:iam::*:role/*", "arn:*:iam::*:role/*"}


def load_policies():
    policies = {}
    for f in sorted(POLICIES_DIR.glob("*.json")):
        if f.name.endswith(".meta.json") or f.name == "_fetch_summary.json":
            continue
        policies[f.stem] = json.loads(f.read_text())
    return policies


def as_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def find_passrole_wildcards(policy_name, statement):
    actions = as_list(statement.get("Action"))
    if statement.get("Effect") != "Allow":
        return None
    if "iam:PassRole" not in actions:
        return None
    resources = as_list(statement.get("Resource"))
    if any(r in PASSROLE_WILDCARD_RESOURCES for r in resources):
        return {
            "policy": policy_name,
            "sid": statement.get("Sid", "(no Sid)"),
            "resource": statement.get("Resource"),
            "condition": statement.get("Condition"),
        }
    return None


def find_tag_gated_conditions(policy_name, statement):
    if statement.get("Effect") != "Allow":
        return None
    condition = statement.get("Condition")
    if not condition:
        return None
    hits = []
    for operator, kv in condition.items():
        if not isinstance(kv, dict):
            continue
        for key in kv:
            if key.startswith(ATTACKER_SETTABLE_CONDITION_PREFIXES):
                hits.append({"operator": operator, "key": key, "value": kv[key]})
    if not hits:
        return None
    return {
        "policy": policy_name,
        "sid": statement.get("Sid", "(no Sid)"),
        "action": statement.get("Action"),
        "tag_conditions": hits,
    }


def find_wildcard_resource_grants(policy_name, statement):
    if statement.get("Effect") != "Allow":
        return None
    resources = as_list(statement.get("Resource"))
    if resources == ["*"]:
        return {
            "policy": policy_name,
            "sid": statement.get("Sid", "(no Sid)"),
            "action": statement.get("Action"),
        }
    return None


ANY_BUCKET_PATTERNS = {"arn:aws:s3:::*", "arn:aws:s3:::*/*", "arn:*:s3:::*", "arn:*:s3:::*/*"}


def find_any_bucket_resources(policy_name, statement):
    if statement.get("Effect") != "Allow":
        return None
    resources = as_list(statement.get("Resource"))
    matches = [r for r in resources if r in ANY_BUCKET_PATTERNS]
    if not matches:
        return None
    return {
        "policy": policy_name,
        "sid": statement.get("Sid", "(no Sid)"),
        "action": statement.get("Action"),
        "resource": matches,
        "condition": statement.get("Condition"),
    }


def analyze(policies):
    passrole_hits = []
    tag_gated_hits = []
    wildcard_resource_hits = []
    any_bucket_hits = []

    for policy_name, doc in policies.items():
        for statement in doc.get("Statement", []):
            r = find_passrole_wildcards(policy_name, statement)
            if r:
                passrole_hits.append(r)

            r = find_tag_gated_conditions(policy_name, statement)
            if r:
                tag_gated_hits.append(r)

            r = find_wildcard_resource_grants(policy_name, statement)
            if r:
                wildcard_resource_hits.append(r)

            r = find_any_bucket_resources(policy_name, statement)
            if r:
                any_bucket_hits.append(r)

    return {
        "policies_analyzed": sorted(policies.keys()),
        "policy_count": len(policies),
        "passrole_wildcard": {
            "count": len(passrole_hits),
            "findings": passrole_hits,
        },
        "tag_gated_condition": {
            "count": len(tag_gated_hits),
            "findings": tag_gated_hits,
        },
        "wildcard_resource_grant": {
            "count": len(wildcard_resource_hits),
            "findings": wildcard_resource_hits,
        },
        "any_bucket_resource": {
            "count": len(any_bucket_hits),
            "findings": any_bucket_hits,
        },
    }


def print_report(result):
    print(f"Policies analyzed: {result['policy_count']}")
    for name in result["policies_analyzed"]:
        print(f"  - {name}")
    print()

    print(f"[1] PassRole statements with a wildcard role Resource: {result['passrole_wildcard']['count']}")
    for f in result["passrole_wildcard"]["findings"]:
        print(f"    {f['policy']} :: Sid={f['sid']} Resource={f['resource']} Condition={f['condition']}")
    print()

    print(f"[2] Statements gated by an attacker-settable tag condition: {result['tag_gated_condition']['count']}")
    for f in result["tag_gated_condition"]["findings"]:
        print(f"    {f['policy']} :: Sid={f['sid']}")
        for tc in f["tag_conditions"]:
            print(f"        {tc['operator']} {tc['key']} = {tc['value']}")
    print()

    print(f"[3] Allow statements with Resource exactly '*': {result['wildcard_resource_grant']['count']}")
    for f in result["wildcard_resource_grant"]["findings"]:
        print(f"    {f['policy']} :: Sid={f['sid']} Action={f['action']}")
    print()

    print(f"[4] Allow statements with an any-bucket S3 Resource (arn:aws:s3:::*): {result['any_bucket_resource']['count']}")
    for f in result["any_bucket_resource"]["findings"]:
        print(f"    {f['policy']} :: Sid={f['sid']} Action={f['action']} Resource={f['resource']} Condition={f['condition']}")
    print()


def main():
    policies = load_policies()
    if not policies:
        print("No policies found in policies/. Run src/fetch_policies.py first.", file=sys.stderr)
        sys.exit(1)

    result = analyze(policies)
    print_report(result)

    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    out_path = EVIDENCE_DIR / "analyze_findings.json"
    out_path.write_text(json.dumps(result, indent=2) + "\n")
    print(f"Full structured findings written to {out_path.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()

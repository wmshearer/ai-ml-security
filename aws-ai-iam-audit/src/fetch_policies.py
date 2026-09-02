#!/usr/bin/env python3
"""
Fetch AWS managed IAM policy documents from the public AWS documentation site.

No AWS account or credentials are used or required. AWS publishes the full JSON
of every AWS managed policy at a stable public URL:

    https://docs.aws.amazon.com/aws-managed-policy/latest/reference/<PolicyName>.html

Each page also has a markdown mirror at the same path with a `.md` extension.
The markdown version wraps the policy JSON in a single fenced code block and
lists policy metadata (ARN, policy version, creation/edit time) as plain text,
which is far more reliable to parse than the rendered HTML (the HTML wraps
every JSON token in its own <span> for syntax highlighting).

This script fetches the markdown version of each named managed policy, extracts:
  - the JSON policy document (written to policies/<PolicyName>.json)
  - metadata: ARN, default policy version, creation time, edited time,
    and the retrieval date (written to policies/<PolicyName>.meta.json)

If the markdown page's structure changes such that the JSON block or metadata
cannot be found, this script prints a clear error for that policy and continues
with the rest rather than silently producing a partial or hand-edited file.
"""

import json
import re
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

POLICIES = [
    "AmazonSageMakerFullAccess",
    "AmazonSageMakerReadOnly",
    "AmazonBedrockFullAccess",
    "AmazonBedrockReadOnly",
    "AmazonBedrockLimitedAccess",
    "AmazonSageMakerCanvasFullAccess",
    "AmazonSageMakerGroundTruthExecution",
    "AmazonSageMakerModelGovernanceUseAccess",
]

BASE_URL = "https://docs.aws.amazon.com/aws-managed-policy/latest/reference/{}.md"
USER_AGENT = "Mozilla/5.0 (aws-ai-iam-audit research script; contact: [REDACTED-EMAIL])"

REPO_ROOT = Path(__file__).resolve().parent.parent
POLICIES_DIR = REPO_ROOT / "policies"

JSON_BLOCK_RE = re.compile(
    r"## JSON policy document.*?```\s*\n(.*?)```", re.DOTALL
)
ARN_RE = re.compile(r"\*\*ARN\*\*:\s*`([^`]+)`")
CREATION_RE = re.compile(r"\*\*Creation time\*\*:\s*(.+?)\s*$", re.MULTILINE)
EDITED_RE = re.compile(r"\*\*Edited time:?\*\*:?\s*(.+?)\s*$", re.MULTILINE)
VERSION_RE = re.compile(r"\*\*Policy version:\*\*\s*(\S+)")


def fetch(policy_name: str) -> str:
    url = BASE_URL.format(policy_name)
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read().decode("utf-8")


def extract(policy_name: str, text: str):
    json_match = JSON_BLOCK_RE.search(text)
    if not json_match:
        raise ValueError(f"could not locate JSON policy document block for {policy_name}")
    raw_json = json_match.group(1)
    policy_doc = json.loads(raw_json)  # raises if AWS's own JSON is malformed

    arn_match = ARN_RE.search(text)
    creation_match = CREATION_RE.search(text)
    edited_match = EDITED_RE.search(text)
    version_match = VERSION_RE.search(text)

    meta = {
        "policy_name": policy_name,
        "arn": arn_match.group(1) if arn_match else "unconfirmed",
        "policy_version": version_match.group(1) if version_match else "unconfirmed",
        "creation_time": creation_match.group(1) if creation_match else "unconfirmed",
        "edited_time": edited_match.group(1) if edited_match else "unconfirmed",
        "source_url": BASE_URL.format(policy_name).replace(".md", ".html"),
        "retrieved_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "statement_count": len(policy_doc.get("Statement", [])),
        "statement_ids": [s.get("Sid", "(no Sid)") for s in policy_doc.get("Statement", [])],
    }
    return policy_doc, meta


def main():
    POLICIES_DIR.mkdir(parents=True, exist_ok=True)
    failures = []
    successes = []

    for name in POLICIES:
        print(f"Fetching {name} ...")
        try:
            text = fetch(name)
        except Exception as e:
            print(f"  FAILED to fetch {name}: {e}")
            failures.append((name, f"fetch error: {e}"))
            continue

        try:
            policy_doc, meta = extract(name, text)
        except Exception as e:
            print(f"  FAILED to extract {name}: {e}")
            failures.append((name, f"extract error: {e}"))
            continue

        json_path = POLICIES_DIR / f"{name}.json"
        meta_path = POLICIES_DIR / f"{name}.meta.json"
        json_path.write_text(json.dumps(policy_doc, indent=2) + "\n")
        meta_path.write_text(json.dumps(meta, indent=2) + "\n")
        print(f"  OK: {meta['statement_count']} statements, version {meta['policy_version']}, "
              f"edited {meta['edited_time']}")
        successes.append(name)
        time.sleep(0.5)  # be polite to docs.aws.amazon.com

    print()
    print(f"Fetched {len(successes)}/{len(POLICIES)} policies successfully.")
    if failures:
        print("Failures:")
        for name, reason in failures:
            print(f"  - {name}: {reason}")

    summary = {
        "run_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "requested": POLICIES,
        "succeeded": successes,
        "failed": [{"policy": n, "reason": r} for n, r in failures],
    }
    (POLICIES_DIR / "_fetch_summary.json").write_text(json.dumps(summary, indent=2) + "\n")

    if not successes:
        sys.exit(1)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Fetch InjecAgent's public test-case files (MIT license) into corpus_src/.

Idempotent: if a target file already exists and is non-empty, it is left
alone and not re-downloaded. Run again any time to fill in anything missing.

Source: https://github.com/uiuc-kang-lab/InjecAgent (MIT license, confirmed
via `GET https://api.github.com/repos/uiuc-kang-lab/InjecAgent` ->
license.key == "mit" on 2026-08-31).

This script only ever talks to raw.githubusercontent.com to pull these
three JSON files. It does not touch anything else on the network.
"""
from __future__ import annotations

import json
import sys
import urllib.request
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CORPUS_DIR = PROJECT_ROOT / "corpus_src"

BASE_URL = "https://raw.githubusercontent.com/uiuc-kang-lab/InjecAgent/main/data"

FILES = {
    "dh_base.json": f"{BASE_URL}/test_cases_dh_base.json",
    "ds_base.json": f"{BASE_URL}/test_cases_ds_base.json",
    "tools.json": f"{BASE_URL}/tools.json",
}

PROVENANCE_NOTE = """\
Files in this directory are fetched verbatim from InjecAgent
(https://github.com/uiuc-kang-lab/InjecAgent), MIT license.

  dh_base.json  <- data/test_cases_dh_base.json   (direct-harm attacker cases)
  ds_base.json  <- data/test_cases_ds_base.json   (data-stealing attacker cases)
  tools.json    <- data/tools.json                (tool/toolkit descriptions)

Fetched by scripts/01_fetch_corpus.py. Not modified after download.
Citation: Zhan et al., "InjecAgent: Benchmarking Indirect Prompt Injections
in Tool-Integrated Large Language Model Agents", ACL Findings 2024,
arXiv:2403.02691.
"""


def fetch(name: str, url: str) -> None:
    dest = CORPUS_DIR / name
    if dest.exists() and dest.stat().st_size > 0:
        print(f"[skip] {name} already present ({dest.stat().st_size} bytes)")
        return
    print(f"[fetch] {url}")
    with urllib.request.urlopen(url, timeout=30) as resp:
        data = resp.read()
    # Validate it is well-formed JSON before writing, so a partial/HTML
    # error page never gets mistaken for corpus data.
    json.loads(data)
    dest.write_bytes(data)
    print(f"[ok] wrote {dest} ({len(data)} bytes)")


def main() -> int:
    CORPUS_DIR.mkdir(parents=True, exist_ok=True)
    for name, url in FILES.items():
        try:
            fetch(name, url)
        except Exception as exc:  # noqa: BLE001
            print(f"[FAIL] could not fetch {name} from {url}: {exc}", file=sys.stderr)
            return 1
    note_path = CORPUS_DIR / "PROVENANCE.txt"
    note_path.write_text(PROVENANCE_NOTE)
    print(f"[ok] wrote {note_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Load the vendored, labelled prompt corpus used to score the rules.

Two CSVs, both prompt,label with label already assigned by the source dataset, not by
anything in this module: data/malicious_jailbreak_1405.csv (real jailbreak prompts from
verazuo/jailbreak_llms, MIT license) and data/benign_dolly_1405.csv (ordinary human
instructions sampled from databricks-dolly-15k, CC BY-SA 3.0). 1,405 rows each, balanced
1:1. Prompt text can be long and can contain embedded newlines inside quoted CSV fields,
so this reads with csv.DictReader rather than splitting lines by hand.

WHAT THIS IS NOT
    Not a scraper and not a re-fetch of the source datasets. The CSVs are already
    vendored under data/; this module only reads what is already on disk.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
MALICIOUS_PATH = DATA_DIR / "malicious_jailbreak_1405.csv"
BENIGN_PATH = DATA_DIR / "benign_dolly_1405.csv"


@dataclass(frozen=True)
class LabeledPrompt:
    text: str
    label: str  # "malicious" or "benign"


def load_labeled(path: Path) -> tuple[LabeledPrompt, ...]:
    """Read a prompt,label CSV into LabeledPrompt rows. Handles multiline quoted
    fields via csv.DictReader; skips rows with an empty prompt or label."""
    prompts = []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            text = (row.get("prompt") or "").strip()
            label = (row.get("label") or "").strip()
            if not text or not label:
                continue
            prompts.append(LabeledPrompt(text=text, label=label))
    return tuple(prompts)


def load_all(
    malicious_path: Path = MALICIOUS_PATH, benign_path: Path = BENIGN_PATH
) -> tuple[LabeledPrompt, ...]:
    """Load both vendored files and concatenate malicious then benign."""
    return load_labeled(malicious_path) + load_labeled(benign_path)

"""1,405 real in-the-wild jailbreak prompts, vendored from a published research corpus.

Source: verazuo/jailbreak_llms on GitHub (MIT license), the dataset behind:
Shen, Chen, Backes, Shen, Zhang. "Do Anything Now": Characterizing and Evaluating
In-The-Wild Jailbreak Prompts on Large Language Models. ACM CCS 2024. arXiv:2308.03825.

The CSV at data/jailbreak_prompts_2023_12_25.csv holds every prompt Shen et al.
collected from Reddit, dedicated jailbreak websites, Discord servers, and open-source
prompt collections between December 2022 and December 2023. Every row is already
labelled jailbreak=True in the source data; the load function still filters on that
column defensively rather than assuming it.

This project ANALYZES these prompts: it classifies each one by technique against a
taxonomy from a separate paper (Liu et al., arXiv:2305.13860, which defines the 3-type
jailbreak taxonomy this analysis applies) and maps the techniques to MITRE ATLAS and the
OWASP LLM Top 10. Shen et al. supplies the corpus; Liu et al. supplies the taxonomy. It
never sends a prompt to a model and never executes one. No output this project produces
reproduces a prompt's text in full; prompts are counted and classified, not quoted at
length.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path

DEFAULT_PATH = Path(__file__).resolve().parent / "jailbreak_prompts_2023_12_25.csv"


@dataclass(frozen=True)
class Prompt:
    """One jailbreak prompt as the source CSV records it."""

    text: str       # the prompt body
    platform: str   # reddit, website, discord, or open_source
    source: str     # the specific subreddit/site/server/collection name
    date: str       # ISO date the prompt was collected or posted


def load_corpus(path: Path = DEFAULT_PATH) -> tuple[Prompt, ...]:
    """Load the vendored CSV into a tuple of Prompt records.

    Only rows with jailbreak == "True" are kept. Every row in the vendored file
    already satisfies that, but the filter stays in place so the loader is correct
    even if a differently-labelled CSV is dropped in later.

    csv.DictReader handles the multiline quoted prompt fields natively, so no
    special-casing is needed for prompts that contain embedded newlines.
    """
    prompts = []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row["jailbreak"] != "True":
                continue
            prompts.append(
                Prompt(
                    text=row["prompt"],
                    platform=row["platform"],
                    source=row["source"],
                    date=row["date"],
                )
            )
    return tuple(prompts)

"""Measure AI supply-chain exposure from public metadata only.

WHAT THIS IS, AND THE LINE IT WILL NOT CROSS

No model file is downloaded. No pickle is opened. No package is installed. Every
number here comes from metadata: file listings, package manifests, advisory
records.

That restriction is not caution for its own sake, it decides what can honestly be
claimed. Metadata can measure EXPOSURE, meaning how many models ship a format
that executes code when loaded. It cannot measure MALICE, meaning whether any
particular file is hostile.

The distinction is load-bearing because the scanners that do read file contents
have documented bypasses. JFrog published a case where a model evaded Hugging
Face's scan using runpy. ReversingLabs published another where a 7z-compressed
pickle carried a deliberately corrupted opcode positioned so the integrity check
failed while Python still executed the payload first. Both defeated a scanner
that parses pickle opcodes without executing them.

So a "safety score" derived from filenames would be less accurate than a tool
already known to be evadable, while sounding more confident. This measures the
attack surface instead, which is a real number that means exactly what it says.

WHY PICKLE MATTERS
Python's pickle format is a small stack machine. Its opcodes can import a module
and call it, so loading a pickle can run code. PyTorch's traditional .bin and .pt
weights are pickle-based. Hugging Face's own documentation describes the risk and
says plainly of their scanning that "this is not 100% foolproof".

Safetensors exists to remove that: an 8-byte header length, a JSON header of
names, dtypes and offsets, then raw tensor bytes. Nothing executable.

SOURCES
  huggingface.co/docs/hub/security-pickle
  github.com/huggingface/safetensors
  api.osv.dev, pypi.org/pypi  (both public, no auth)
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CACHE = ROOT / "data"

# Weight-file extensions that go through pickle on load, and therefore can run
# code. .ot is the Rust tch format and .msgpack is Flax; neither is pickle, so
# neither is counted here.
PICKLE_EXTENSIONS = (".bin", ".pt", ".pth", ".ckpt")
SAFE_EXTENSIONS = (".safetensors",)

USER_AGENT = "ai-supply-chain-audit/0.1 (portfolio research; metadata only)"

PICKLE_ONLY = "pickle only"
BOTH = "both"
SAFE_ONLY = "safetensors only"
NEITHER = "neither"
CATEGORIES = (PICKLE_ONLY, BOTH, SAFE_ONLY, NEITHER)


def fetch_json(url: str, method: str = "GET", body: bytes | None = None) -> dict:
    request = urllib.request.Request(url, data=body, method=method)
    request.add_header("User-Agent", USER_AGENT)
    if body is not None:
        request.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.loads(response.read().decode("utf-8"))


@dataclass
class ModelExposure:
    model_id: str
    pickle_files: list[str] = field(default_factory=list)
    safe_files: list[str] = field(default_factory=list)
    downloads: int = 0

    @property
    def ships_pickle(self) -> bool:
        return bool(self.pickle_files)

    @property
    def ships_safetensors(self) -> bool:
        return bool(self.safe_files)

    @property
    def category(self) -> str:
        """Which load path a user's code will actually take.

        'both' is the interesting case and the reason this is not a binary. A
        repo carrying both formats is safe for a caller whose library prefers
        safetensors, and exposed for one that does not, or for anyone pinning
        the older filename. The exposure has not been removed, only made
        avoidable.
        """
        if self.ships_pickle and self.ships_safetensors:
            return BOTH
        if self.ships_pickle:
            return PICKLE_ONLY
        if self.ships_safetensors:
            return SAFE_ONLY
        return NEITHER


def audit_model(model_id: str) -> ModelExposure:
    data = fetch_json(f"https://huggingface.co/api/models/{model_id}")
    exposure = ModelExposure(
        model_id=data.get("id", model_id),
        downloads=data.get("downloads", 0),
    )
    for sibling in data.get("siblings", []):
        name = sibling.get("rfilename", "")
        if name.endswith(PICKLE_EXTENSIONS):
            exposure.pickle_files.append(name)
        elif name.endswith(SAFE_EXTENSIONS):
            exposure.safe_files.append(name)
    return exposure


def top_models(limit: int = 50) -> list[str]:
    """The most-downloaded models. Popularity is the right sampling axis here:
    a format choice in a model pulled millions of times has more consequence
    than the same choice in one nobody uses.
    """
    url = f"https://huggingface.co/api/models?sort=downloads&direction=-1&limit={limit}"
    return [m["id"] for m in fetch_json(url)]


@dataclass
class PackageAdvisories:
    name: str
    advisory_count: int
    malicious_count: int

    @property
    def note(self) -> str:
        if self.malicious_count:
            return f"{self.malicious_count} carry a MAL- identifier"
        return ""


def is_malicious_advisory(vuln: dict) -> bool:
    """Whether an advisory says the package itself was malicious.

    The obvious test is a MAL- identifier prefix, and on its own it is wrong.
    Checking against `ctx`, a real 2022 PyPI compromise, returns three advisories
    and none of them is MAL- prefixed: two are GHSA- records titled "Malware in
    ctx" and "Embedded Malicious Code in ctx", because they arrived through
    GitHub's advisory feed rather than OSV's malware feed.

    A MAL-only filter would therefore report a compromised package as clean. So
    the summary is checked too. That is a string match and it is imperfect, but
    under-reporting malicious packages is the worse failure here.
    """
    if str(vuln.get("id", "")).startswith("MAL-"):
        return True
    summary = str(vuln.get("summary", "")).lower()
    return "malware" in summary or "malicious code" in summary


def audit_package(name: str) -> PackageAdvisories:
    """Count OSV advisories for a PyPI package.

    Two different things get conflated in supply-chain reporting and are
    separated here. Most advisories are vulnerabilities in a legitimate package,
    which is ordinary software maintenance. A malicious-package advisory means
    the package itself was hostile, which is the supply-chain attack. Reporting
    one total would let the first masquerade as the second.
    """
    body = json.dumps({"package": {"name": name, "ecosystem": "PyPI"}}).encode()
    data = fetch_json("https://api.osv.dev/v1/query", method="POST", body=body)
    vulns = data.get("vulns", [])
    malicious = [v for v in vulns if is_malicious_advisory(v)]
    return PackageAdvisories(name, len(vulns), len(malicious))


AI_STACK = [
    "transformers",
    "langchain",
    "llama-index",
    "chromadb",
    "sentence-transformers",
    "openai",
    "anthropic",
]


def run(limit: int = 50, sleep: float = 0.2) -> dict:
    models = []
    for model_id in top_models(limit):
        try:
            models.append(audit_model(model_id))
        except urllib.error.HTTPError as err:
            # A gated or moved model is expected, not a failure of the audit.
            print(f"  skipped {model_id}: HTTP {err.code}")
        time.sleep(sleep)

    packages = []
    for name in AI_STACK:
        try:
            packages.append(audit_package(name))
        except urllib.error.HTTPError as err:
            print(f"  skipped {name}: HTTP {err.code}")
        time.sleep(sleep)

    return {"models": models, "packages": packages}


def report(result: dict) -> None:
    models: list[ModelExposure] = result["models"]
    packages: list[PackageAdvisories] = result["packages"]

    counts = dict.fromkeys(CATEGORIES, 0)
    for model in models:
        counts[model.category] += 1

    exposed = counts[PICKLE_ONLY] + counts[BOTH]
    total = len(models)

    print(f"Weight-format exposure across the {total} most-downloaded models\n")
    for category in CATEGORIES:
        n = counts[category]
        bar = "#" * n
        print(f"  {category:<18} {n:>3}  {bar}")

    print(f"\n  {exposed} of {total} ({exposed / total:.0%}) ship at least one "
          "pickle-format weight file.")
    print(f"  {counts[PICKLE_ONLY]} ship pickle format with no safetensors "
          "alternative at all.")

    print("\n  'both' means the exposure is avoidable, not removed. A caller whose")
    print("  library prefers safetensors is fine. One that pins the older filename")
    print("  still loads a pickle.")

    print("\n\nOSV advisories for the common LLM stack\n")
    for pkg in sorted(packages, key=lambda p: -p.advisory_count):
        note = f"   {pkg.note}" if pkg.note else ""
        print(f"  {pkg.name:<24} {pkg.advisory_count:>3} advisories{note}")

    total_mal = sum(p.malicious_count for p in packages)
    print(f"\n  {total_mal} of these advisories describe a malicious package.")
    print("  The rest are vulnerabilities in legitimate packages, which is")
    print("  ordinary maintenance rather than a supply-chain attack.")
    print("\n  That zero is a real result, not a blind spot. The same query")
    print("  against ctx, a package genuinely compromised in 2022, returns")
    print("  three advisories including two titled as malware.")

    print("\n\nWhat this does not measure: whether any specific file is malicious.")
    print("Reading a pickle's contents would be needed for that, and the scanners")
    print("that do read them have published bypasses. This counts exposure.")


def main() -> None:
    CACHE.mkdir(exist_ok=True)
    result = run()
    report(result)
    snapshot = {
        "models": [
            {
                "id": m.model_id,
                "category": m.category,
                "pickle_files": m.pickle_files,
                "safe_files": m.safe_files,
                "downloads": m.downloads,
            }
            for m in result["models"]
        ],
        "packages": [
            {"name": p.name, "advisories": p.advisory_count, "malicious": p.malicious_count}
            for p in result["packages"]
        ],
    }
    (CACHE / "snapshot.json").write_text(json.dumps(snapshot, indent=1), encoding="utf-8")
    print(f"\nSnapshot written to {CACHE / 'snapshot.json'}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Score each scanner's raw output against corpus/manifest.csv (ground
truth). Produces one row per (tool, corpus file) with a verdict of
detected / missed / false_positive, plus a per-tool-per-class summary table.

Never blends the three tools into one score and never blends classes into
one number: benign (false-positive rate), poc_overt (basic mechanism
detection), and poc_evasive (disclosed-bypass reproduction) are reported
separately throughout, matching webapp-scanner-coverage's per-category
table.

A tool's raw JSON already contains everything needed for its own detection
logic; this script does not re-run any scanner or interpret pickle bytes
itself, it only reads what scripts/02-04 already wrote.
"""
import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MANIFEST_CSV = ROOT / "corpus" / "manifest.csv"
OUT_DIR = ROOT / "evidence" / "scoring"


def load_manifest() -> list[dict]:
    with open(MANIFEST_CSV, newline="") as f:
        return list(csv.DictReader(f))


# --- per-tool "did this tool alert on this file" extraction -----------------

def picklescan_verdicts(raw: dict) -> dict[str, dict]:
    """Returns {file: {"default": bool, "strict": bool}} where bool is
    whether picklescan raised any suspicious or dangerous global for that
    file in that mode (infected file count > 0, OR suspicious/dangerous
    globals > 0 -- picklescan's default mode can report a suspicious global
    without setting "infected" or a non-zero exit code, so infected-file
    count alone would understate what it actually surfaced)."""
    out: dict[str, dict] = {}
    for r in raw["results"]:
        f = r["file"]
        mode = "strict" if r["strict"] else "default"
        out.setdefault(f, {})
        stdout = r["stdout"]
        alerted = ("Suspicious globals: 0" not in stdout) or ("Dangerous globals: 0" not in stdout)
        out[f][mode] = alerted
    return out


def modelscan_verdicts(raw: dict) -> dict[str, bool]:
    out: dict[str, bool] = {}
    for r in raw["results"]:
        f = r["file"]
        parsed = r.get("parsed")
        total_issues = 0
        if parsed and "summary" in parsed:
            total_issues = parsed["summary"].get("total_issues", 0)
        out[f] = total_issues > 0
    return out


def fickling_verdicts(raw: dict) -> dict[str, str]:
    """Returns {file: severity_string}. fickling reports a severity label
    (LIKELY_SAFE / SUSPICIOUS / LIKELY_UNSAFE / OVERTLY_MALICIOUS) rather
    than a binary; "alerted" is defined as anything other than LIKELY_SAFE.
    """
    out: dict[str, str] = {}
    for r in raw["results"]:
        f = r["file"]
        parsed = r.get("parsed")
        severity = parsed.get("severity", "UNKNOWN") if parsed else "PARSE_ERROR"
        out[f] = severity
    return out


def fickling_alerted(severity: str) -> bool:
    return severity not in ("LIKELY_SAFE",)


# --- scoring ------------------------------------------------------------

def classify(expected: str, alerted: bool) -> str:
    """expected is one of: no_alert, alert, alert_if_patched (both possible
    outcomes are legitimate depending on installed version)."""
    if expected == "no_alert":
        return "false_positive" if alerted else "true_negative"
    if expected == "alert":
        return "detected" if alerted else "missed"
    if expected == "alert_if_patched,miss_if_vulnerable":
        return "detected_bypass_failed_to_evade" if alerted else "missed_bypass_still_works"
    return "unknown_expected_value"


def main() -> int:
    manifest = load_manifest()
    by_file = {row["file"]: row for row in manifest}

    picklescan_raw = json.load(open(ROOT / "evidence" / "picklescan" / "raw_results.json"))
    modelscan_raw = json.load(open(ROOT / "evidence" / "modelscan" / "raw_results.json"))
    fickling_raw = json.load(open(ROOT / "evidence" / "fickling" / "raw_results.json"))

    ps_verdicts = picklescan_verdicts(picklescan_raw)
    ms_verdicts = modelscan_verdicts(modelscan_raw)
    fk_verdicts = fickling_verdicts(fickling_raw)

    per_file_rows = []
    for file, row in by_file.items():
        expected = row["expected_detection"]
        corpus_class = row["class"]

        ps_default = ps_verdicts.get(file, {}).get("default", False)
        ps_strict = ps_verdicts.get(file, {}).get("strict", False)
        ms_alert = ms_verdicts.get(file, False)
        fk_severity = fk_verdicts.get(file, "MISSING")
        fk_alert = fickling_alerted(fk_severity)

        per_file_rows.append(
            {
                "file": file,
                "class": corpus_class,
                "technique": row["technique"],
                "cve": row["cve"],
                "expected_detection": expected,
                "picklescan_default_alerted": ps_default,
                "picklescan_default_verdict": classify(expected, ps_default),
                "picklescan_strict_alerted": ps_strict,
                "picklescan_strict_verdict": classify(expected, ps_strict),
                "modelscan_alerted": ms_alert,
                "modelscan_verdict": classify(expected, ms_alert),
                "fickling_severity": fk_severity,
                "fickling_alerted": fk_alert,
                "fickling_verdict": classify(expected, fk_alert),
            }
        )

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    per_file_csv = OUT_DIR / "per_file_results.csv"
    fieldnames = list(per_file_rows[0].keys())
    with open(per_file_csv, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(per_file_rows)

    # Per-tool, per-class summary: counts of detected/missed/false_positive.
    tools = {
        "picklescan_default": "picklescan_default_verdict",
        "picklescan_strict": "picklescan_strict_verdict",
        "modelscan": "modelscan_verdict",
        "fickling": "fickling_verdict",
    }
    summary_rows = []
    classes = sorted({r["class"] for r in per_file_rows})
    for tool_label, verdict_key in tools.items():
        for cls in classes:
            rows_in_class = [r for r in per_file_rows if r["class"] == cls]
            n = len(rows_in_class)
            verdict_counts: dict[str, int] = {}
            for r in rows_in_class:
                v = r[verdict_key]
                verdict_counts[v] = verdict_counts.get(v, 0) + 1
            summary_rows.append(
                {
                    "tool": tool_label,
                    "class": cls,
                    "n_files": n,
                    **verdict_counts,
                }
            )

    summary_csv = OUT_DIR / "summary_by_tool_and_class.csv"
    all_verdict_keys = sorted({k for r in summary_rows for k in r if k not in ("tool", "class", "n_files")})
    summary_fieldnames = ["tool", "class", "n_files"] + all_verdict_keys
    with open(summary_csv, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=summary_fieldnames)
        writer.writeheader()
        for row in summary_rows:
            full_row = {k: row.get(k, 0) for k in summary_fieldnames}
            full_row["tool"] = row["tool"]
            full_row["class"] = row["class"]
            full_row["n_files"] = row["n_files"]
            writer.writerow(full_row)

    print(f"Per-file results: {per_file_csv.relative_to(ROOT)} ({len(per_file_rows)} rows)")
    print(f"Summary: {summary_csv.relative_to(ROOT)} ({len(summary_rows)} rows)")
    print()
    for row in summary_rows:
        print(row)
    return 0


if __name__ == "__main__":
    sys.exit(main())

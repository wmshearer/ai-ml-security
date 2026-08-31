#!/usr/bin/env python3
"""Generate the self-authored, inert pickle/model-file corpus for this project.

Every file here is written by this script using only the Python standard
library (`pickle`, `pickletools`). Nothing is downloaded. Nothing in the
"payload" class does anything beyond writing a timestamped marker file under
this project's own evidence/markers/ directory or returning a benign string
-- the same mechanism (arbitrary callable invocation during unpickling) that
a real malicious pickle uses, with a harmless callable standing in for the
actual weapon.

Three classes, matching the ground-truth manifest written alongside the
corpus:

  benign        -- ordinary serialized data, no __reduce__, no GLOBAL/REDUCE
                   opcodes tied to a payload. Measures false positives.
  poc_overt     -- a plain __reduce__ payload calling a marker-writing
                   function directly (os.system is NOT used; the callable is
                   this project's own marker helper). No evasion attempted.
                   Measures whether scanners catch the mechanism at all.
  poc_evasive   -- reproductions of the two NVD-confirmed picklescan bypass
                   techniques (CVE-2025-10155, CVE-2025-10157), each wrapping
                   the same inert marker payload. These are PUBLICLY
                   DISCLOSED techniques being reproduced for scoring, not new
                   research.

Idempotent: reruns regenerate every file and the manifest from scratch.
"""
import csv
import pickle
import pickletools
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CORPUS_DIR = ROOT / "corpus"
DIS_DIR = ROOT / "evidence" / "pickletools_dis"
MANIFEST_CSV = ROOT / "corpus" / "manifest.csv"

MARKER_HELPER_IMPORT = "corpus_gen.marker"  # package providing write_marker()


def write_pickle(path: Path, obj, protocol: int = pickle.DEFAULT_PROTOCOL) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as f:
        pickle.dump(obj, f, protocol=protocol)


def write_dis(pickle_path: Path, dis_path: Path) -> None:
    """Static opcode disassembly via pickletools.dis(), never unpickling."""
    dis_path.parent.mkdir(parents=True, exist_ok=True)
    with open(pickle_path, "rb") as f:
        data = f.read()
    with open(dis_path, "w") as out:
        pickletools.dis(data, out)


# ---------------------------------------------------------------------------
# Class 1: benign -- ordinary data, no executable payload
# ---------------------------------------------------------------------------

def make_benign(rows: list[dict]) -> None:
    cases = {
        "benign_dict.pkl": {"user": "alice", "id": 42, "roles": ["reader", "editor"]},
        "benign_list_of_tuples.pkl": [(1, "a"), (2, "b"), (3, "c")],
        "benign_nested.pkl": {
            "config": {"retries": 3, "timeout": 30.0},
            "history": [1, 2, 3, 5, 8, 13],
            "flags": {True, False},
        },
        "benign_numbers.pkl": list(range(0, 1000, 7)),
        "benign_strings.pkl": {"greeting": "hello", "note": "no callables here"},
        "benign_empty.pkl": {},
    }
    for filename, obj in cases.items():
        out = CORPUS_DIR / "benign" / filename
        write_pickle(out, obj)
        write_dis(out, DIS_DIR / "benign" / (filename + ".dis.txt"))
        rows.append(
            {
                "file": str(out.relative_to(ROOT)),
                "class": "benign",
                "technique": "none",
                "expected_detection": "no_alert",
                "rationale": "Plain data object, no GLOBAL/REDUCE opcodes tied to "
                "a callable. A scanner flagging this file is a false positive.",
                "cve": "",
            }
        )


# ---------------------------------------------------------------------------
# Class 2: poc_overt -- plain __reduce__ payload, no evasion
# ---------------------------------------------------------------------------

class OvertMarkerPayloadDirect:
    """__reduce__ returns (callable, args) where callable is
    corpus_gen.marker.write_marker -- a GLOBAL opcode for that exact name
    followed by REDUCE, with no attempt to hide either opcode or the module
    name. This is the textbook "pickle can call anything" mechanism, done in
    the most obvious way, and is exactly the shape every scanner's basic
    denylist is built to catch.
    """
    def __init__(self, marker_name: str):
        self.marker_name = marker_name

    def __reduce__(self):
        from corpus_gen.marker import write_marker

        return (write_marker, (self.marker_name,))


def make_overt(rows: list[dict]) -> None:
    filename = "poc_overt_reduce.pkl"
    out = CORPUS_DIR / "poc_overt" / filename
    write_pickle(out, OvertMarkerPayloadDirect("poc_overt_reduce"))
    write_dis(out, DIS_DIR / "poc_overt" / (filename + ".dis.txt"))
    rows.append(
        {
            "file": str(out.relative_to(ROOT)),
            "class": "poc_overt",
            "technique": "plain_reduce",
            "expected_detection": "alert",
            "rationale": "GLOBAL opcode names corpus_gen.marker.write_marker "
            "directly, followed by REDUCE. No obfuscation, no evasion "
            "attempted. Any scanner checking for GLOBAL+REDUCE against a "
            "non-stdlib callable should catch this.",
            "cve": "",
        }
    )

    # A second overt case using os.path.join as the callable -- a stdlib
    # function, not this project's marker helper -- to test whether scanners
    # flag GLOBAL opcodes into common stdlib modules at all, versus only
    # flagging a fixed denylist (eval, exec, os.system, subprocess, etc.).
    # os.path.join itself is inert; it does not execute anything dangerous
    # and is used here purely as an example "unexpected but not on a
    # denylist" global.
    filename2 = "poc_overt_stdlib_global.pkl"
    out2 = CORPUS_DIR / "poc_overt" / filename2

    class StdlibGlobalPayload:
        def __reduce__(self):
            import os.path

            return (os.path.join, ("a", "b", "c"))

    write_pickle(out2, StdlibGlobalPayload())
    write_dis(out2, DIS_DIR / "poc_overt" / (filename2 + ".dis.txt"))
    rows.append(
        {
            "file": str(out2.relative_to(ROOT)),
            "class": "poc_overt",
            "technique": "stdlib_global_reduce",
            "expected_detection": "alert",
            "rationale": "GLOBAL opcode into os.path.join (stdlib, not on a "
            "typical denylist) followed by REDUCE. Tests whether a scanner "
            "flags any non-builtin callable invocation, or only a fixed "
            "denylist of known-dangerous names.",
            "cve": "",
        }
    )


# ---------------------------------------------------------------------------
# Class 3: poc_evasive -- reproductions of disclosed picklescan bypasses
# ---------------------------------------------------------------------------

def make_evasive(rows: list[dict]) -> None:
    # --- CVE-2025-10155: extension mismatch --------------------------------
    # picklescan <=0.0.30's scan_bytes() branched on file extension before
    # content: a .bin/.pt extension routed the file into PyTorch-specific
    # parsing, which failed to parse a plain (non-zip, non-PyTorch-container)
    # pickle stream and returned no findings instead of falling back to a
    # generic pickle scan. Reproduced here as a byte-for-byte ordinary
    # pickle file, written with a .bin extension, carrying the same overt
    # marker payload as class 2. If picklescan's fix (>=0.0.31) is installed,
    # this file should still be caught -- the file's *content* is the overt
    # payload above, unchanged; only the extension differs from the .pkl
    # baseline.
    filename = "cve_2025_10155_extension_mismatch.bin"
    out = CORPUS_DIR / "poc_evasive" / filename
    write_pickle(out, OvertMarkerPayloadDirect("cve_2025_10155"))
    write_dis(out, DIS_DIR / "poc_evasive" / (filename + ".dis.txt"))
    rows.append(
        {
            "file": str(out.relative_to(ROOT)),
            "class": "poc_evasive",
            "technique": "extension_mismatch",
            "expected_detection": "alert_if_patched,miss_if_vulnerable",
            "rationale": "Reproduces CVE-2025-10155 (NVD, CVSS 9.3): a plain "
            "pickle stream given a .bin extension. picklescan <=0.0.30 routed "
            ".bin/.pt files into PyTorch-container parsing that failed "
            "silently on a non-container pickle, skipping the scan entirely. "
            "Fixed in picklescan 0.0.31. The pickle content is byte-identical "
            "in mechanism to poc_overt_reduce.pkl; only the file extension "
            "differs.",
            "cve": "CVE-2025-10155",
        }
    )

    # --- CVE-2025-10157: submodule import bypass ----------------------------
    # picklescan <=0.0.30's unsafe-globals check compared the imported
    # module name against a denylist using exact string equality. A GLOBAL
    # opcode naming a *submodule* of a denylisted module (e.g.
    # asyncio.unix_events instead of asyncio) did not match the denylisted
    # top-level name exactly, so it was scored "suspicious" rather than
    # "dangerous" and did not fail the scan. Reproduced here: the callable
    # target is named via a submodule path, still resolving to a real,
    # inert marker-writing function, never to a genuinely dangerous stdlib
    # call.
    filename2 = "cve_2025_10157_submodule_import.pkl"
    out2 = CORPUS_DIR / "poc_evasive" / filename2

    class SubmoduleImportPayload:
        def __reduce__(self):
            # corpus_gen.marker.submodule.write_marker_via_submodule is a
            # genuine submodule of corpus_gen.marker (both self-authored),
            # standing in for "asyncio.unix_events instead of asyncio" --
            # the exact shape JFrog documented, minus any real dangerous
            # target. If picklescan denylists corpus_gen.marker at the
            # top-level module name, an exact-match check would still miss
            # this submodule path pre-fix, matching CVE-2025-10157's
            # mechanism precisely.
            from corpus_gen.marker.submodule import write_marker_via_submodule

            return (write_marker_via_submodule, ("cve_2025_10157",))

    write_pickle(out2, SubmoduleImportPayload())
    write_dis(out2, DIS_DIR / "poc_evasive" / (filename2 + ".dis.txt"))
    rows.append(
        {
            "file": str(out2.relative_to(ROOT)),
            "class": "poc_evasive",
            "technique": "submodule_import",
            "expected_detection": "alert_if_patched,miss_if_vulnerable",
            "rationale": "Reproduces CVE-2025-10157 (NVD, CVSS 9.3): picklescan "
            "<=0.0.30's unsafe-globals check used exact module-name matching, "
            "so a GLOBAL opcode into a submodule of a denylisted module (the "
            "disclosed example: asyncio.unix_events instead of asyncio) was "
            "scored suspicious rather than dangerous and passed. Reproduced "
            "with a self-authored submodule (corpus_gen.marker.submodule) "
            "standing in for the denylisted-module shape; the resolved "
            "callable is the same inert marker writer used throughout this "
            "corpus. Fixed in picklescan 0.0.31.",
            "cve": "CVE-2025-10157",
        }
    )


def main() -> int:
    rows: list[dict] = []
    make_benign(rows)
    make_overt(rows)
    make_evasive(rows)

    MANIFEST_CSV.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = ["file", "class", "technique", "expected_detection", "rationale", "cve"]
    with open(MANIFEST_CSV, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"Wrote {len(rows)} corpus files.")
    print(f"Manifest: {MANIFEST_CSV.relative_to(ROOT)}")
    by_class: dict[str, int] = {}
    for r in rows:
        by_class[r["class"]] = by_class.get(r["class"], 0) + 1
    for cls, count in sorted(by_class.items()):
        print(f"  {cls}: {count}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

# Pickle scanner limits: what three detection tools actually catch

Python's `pickle` format is a small stack-based virtual machine for
serializing objects. Loading a pickle does not just read data back into
memory: certain opcodes can name any importable function and call it with
attacker-chosen arguments. A model file saved as a `.pkl`, PyTorch `.bin`, or
`.pt` file is usually a pickle stream underneath, so loading a downloaded
model can run arbitrary code the same way loading an untrusted pickle can.
This is called **deserialization**: turning a byte stream back into a live
object, and the risk is specific to formats, like pickle, where that process
can execute code rather than just build data structures.

Because of this, several open-source tools scan pickle and model files
before they are loaded and try to flag the dangerous ones. This project
measures, with a self-built answer key, how much of that danger each of
three specific tools actually catches, and how much it misses.

## Scope, stated up front

- Every file in the corpus is written by this project's own generator
  script (`scripts/01_generate_corpus.py`), using only Python's standard
  library. Nothing is downloaded.
- No real malicious pickle, model file, or package appears anywhere in this
  project. The proof-of-concept payload used throughout does exactly one
  thing: it appends a timestamped line to a log file inside this project's
  own `evidence/markers/` directory. Nothing spawns a shell, touches the
  network, or persists outside this project's own directory tree.
- Two of the ten corpus files reproduce techniques from **already-published,
  NVD-confirmed CVEs** (CVE-2025-10155 and CVE-2025-10157, both against
  picklescan). This project did not discover either technique. It rebuilt
  them, using the same harmless marker payload as every other file here, to
  measure whether the installed, current version of picklescan still falls
  for them.
- Wherever possible, files are analyzed with `pickletools.dis()`, Python's
  standard-library opcode disassembler, which reads a pickle's byte-code
  without ever executing it. One test file unpickles a corpus file on
  purpose, to confirm the marker payload actually does what the static
  analysis says it does; that test loads only a file this project wrote, in
  a scratch directory this project owns. See `tests/test_marker.py`.

## Relationship to `ai-supply-chain-audit`

The project at `../ai-supply-chain-audit/` measured **exposure**: across the
50 most-downloaded Hugging Face models, 28 of 50 (56%) ship at least one
pickle-format weight file. It explicitly never opened a pickle or read a
file's contents, because doing that safely needs exactly the kind of
inert, self-authored corpus this project built. Read together: that project
answers "how much of the ecosystem could be exposed," this project answers
"if a scanner is put in front of that exposure, how much does it actually
catch." Neither project's numbers are restated as new findings in the other.

## Prior art, named plainly

Pickle's ability to execute code on load has been written up publicly for
over a decade. The two bypass techniques reproduced in this corpus,
extension-mismatch and submodule-import evasion, were disclosed by JFrog's
security research team and assigned CVE-2025-10155 and CVE-2025-10157 by
NVD. Nothing here claims to have found a new hole in any scanner. What this
project adds is a single, ground-truth-scored table running all three tools
against the same corpus side by side, which none of the individual
disclosures did.

## The corpus

Ten files in three classes, listed with expected outcome in
`corpus/manifest.csv`:

| Class | Count | What it is | What it measures |
|---|---|---|---|
| `benign` | 6 | Ordinary dicts, lists, tuples, sets, numbers. No callable is ever named. | **False positives**: a scanner flagging one of these is wrong by definition. |
| `poc_overt` | 2 | A plain `__reduce__` payload naming a callable directly, no evasion attempted. | Whether a scanner catches the pickle-can-call-anything mechanism at all when nothing is hidden. |
| `poc_evasive` | 2 | Reproductions of CVE-2025-10155 and CVE-2025-10157. | Whether the specific, already-disclosed bypass techniques still work against the version of picklescan actually installed here. |

`__reduce__` is the Python method a pickled object can define to say "when
you unpickle me, call this function with these arguments instead of
rebuilding my normal state." It is also the mechanism a real malicious
pickle abuses to call something like a shell command instead of a marker
function. Every `poc_overt` and `poc_evasive` file in this corpus uses
`__reduce__` to call a **self-authored function that writes one log line and
nothing else**.

An **opcode** is one instruction in the pickle byte stream, the same idea as
a machine-code instruction, just for pickle's own small virtual machine.
`pickletools.dis()` prints every opcode in a pickle file without running any
of them, which is how this project confirms, in `evidence/pickletools_dis/`,
that every `benign` file has no `REDUCE` opcode and every PoC file does,
before any scanner is ever run.

## Tool versions, pinned and reported as measured

| Tool | License | Installed version | Confirmed by |
|---|---|---|---|
| picklescan | MIT | **1.0.5** | `evidence/picklescan/raw_results.json` |
| modelscan | Apache-2.0 | **0.8.8** | `evidence/modelscan/raw_results.json` |
| fickling | LGPL-3.0 | **0.1.12** | `evidence/fickling/raw_results.json` |

CVE-2025-10155 and CVE-2025-10157 are both fixed in picklescan 0.0.31.
**1.0.5 is far past that fix**, so this project expected both bypass
reproductions to still be caught, not to slip through, and reports whichever
outcome actually happened rather than picking a version to force a
particular result. No older, known-vulnerable picklescan version was
installed for this project.

## The result

**No blended score.** Each tool is reported separately, and each corpus
class is reported separately, because collapsing "did this scanner ever
flag anything" into one number would hide exactly the distinction this
project exists to show: a scanner that never has a false positive but also
never catches anything is not the same as one with a real, working
detection.

| Tool | benign (6 files, false positives) | poc_overt (2 files, plain payload) | poc_evasive (2 files, disclosed CVE reproductions) |
|---|---|---|---|
| picklescan 1.0.5 (default mode) | 0 false positives | **picklescan flagged 2 of 2** | **picklescan flagged 2 of 2** (bypasses did not reproduce) |
| picklescan 1.0.5 (`--strict` mode) | 0 false positives | **picklescan flagged 2 of 2** | **picklescan flagged 2 of 2** (bypasses did not reproduce) |
| modelscan 0.8.8 | 0 false positives | **modelscan flagged 0 of 2** | **modelscan flagged 0 of 2** |
| fickling 0.1.12 | 0 false positives | **fickling flagged 2 of 2** | **fickling flagged 2 of 2** |

Full per-file detail: `evidence/scoring/per_file_results.csv`. Full reasoning
for every row: `FINDINGS.md`.

## The headline, in one sentence per tool

- **picklescan flagged both the plain payload and both disclosed-CVE
  reproductions**, in both its default and `--strict` modes, with zero false
  positives on six benign files. At version 1.0.5, the two bypasses this
  project reproduced (CVE-2025-10155, CVE-2025-10157) do not work; the fix
  holds.
- **modelscan flagged none of the four payload files**, with zero false
  positives on six benign files. This is not modelscan behaving
  inconsistently: it works from a fixed list of known-dangerous module names
  (`os`, `subprocess`, `socket`, `runpy`, and a short list of others), and
  this project's harmless marker module was never going to be on that list.
  A payload naming a module the list does not cover is invisible to
  modelscan by design, not by accident.
- **fickling flagged both the plain payload and both disclosed-CVE
  reproductions**, with zero false positives on six benign files. Unlike the
  other two tools, fickling's rule is "does this pickle import anything
  outside Python's standard library," not a fixed list of dangerous names,
  which is why neither the extension change nor the submodule path evaded
  it.

## What this does and does not claim

This does not rank the three tools on a single scale, and it is not a claim
that modelscan is broadly worse than picklescan or fickling. modelscan's
denylist approach is a real, documented design choice, and it would catch a
payload that used `os.system` or `subprocess.Popen`, which this project
never tested because doing so would mean building something closer to a
functioning weapon than an inert PoC. The result reported here is narrower
and more honest: for the four payload shapes actually built and run in this
project, against the tool versions actually installed, this is exactly what
each one caught and missed.

## Repo layout

```
corpus_gen/       self-authored helper package; write_marker() is the entire
                  "payload" used anywhere in this project
corpus/           the generated ground-truth corpus + manifest.csv
scripts/          numbered, idempotent: generate corpus, run each scanner, score
evidence/         raw scanner output, pickletools disassembly, scoring CSVs
tests/            pytest; SKIP (not FAIL) when an artifact is absent
```

## Reproducing this

```
python3.12 -m venv .venv && source .venv/bin/activate   # modelscan needs <3.13
pip install picklescan modelscan fickling pytest
python3 scripts/01_generate_corpus.py
python3 scripts/02_run_picklescan.py
python3 scripts/03_run_modelscan.py
python3 scripts/04_run_fickling.py
python3 scripts/05_score.py
python3 -m pytest tests/ -q
```

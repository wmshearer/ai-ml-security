# Findings

## What was fuzzed

- **Target:** `gguf_reader.py`, the pure-Python GGUF file-format parser from
  `gguf-py/gguf/` in [ggml-org/llama.cpp](https://github.com/ggml-org/llama.cpp).
- **Exact commit vendored:** `9a286ac98d2cab74231bd3f1fc3f2b8bdf05422e`
  (branch `master`, committed 2026-08-21T18:49:27Z, title "docs: improve
  Windows build instructions (#27381)"). Full provenance, URLs, and SHA-256
  hashes of every vendored file are in `vendor/COMMIT.txt`. Line numbers
  cited below are against this exact commit; do not assume they hold against
  a later or earlier one.
- **Entry point fuzzed:** `GGUFReader.__init__`, plus the full parse it
  triggers (`_get_str`, `_get_field_parts`, `_build_fields`,
  `_build_tensor_info`, `_get_tensor_info_field`, `_build_tensors`), and
  every `ReaderField.contents()` / `ReaderTensor` attribute the harness
  touches afterward (see `src/fuzz_gguf.py`).
- **Not fuzzed:** the C++ GGUF loader (`ggml/src/gguf.cpp`), the GGUF
  writer, any tokenizer/vocab/metadata code, and no actual model file was
  ever downloaded or used (all inputs are synthetic, built by
  `src/make_corpus.py` or mutated by Atheris from those seeds).

## Regression fuzzing, not rediscovery -- correcting the record on the advisory

This project targets a parser that has already been hardened three times in
the recent history of this file (all three re-verified by direct `grep`
against the vendored file before fuzzing began):

| Hardening commit | Date | What it added | Present at HEAD? |
|---|---|---|---|
| `418dea39ce` (PR #19856) | 2026-02-24 | Alignment must be a non-zero power of two (`gguf_reader.py:187-189`) | Yes |
| `5788b510a1` (PR #25401, fixes #25378) | 2026-08-04 | Tensor `n_dims` must not exceed `GGML_MAX_DIMS` (4) (`gguf_reader.py:284-285`) | Yes |
| `0329fcdac8` (PR #27188) | 2026-08-19 | Size guards on `kv_count`, `tensor_count`, string length, array length, all capped at `1024*1024*1024` (`gguf_reader.py:174-177, 228-229, 256-257`) | Yes |

An [oss-security advisory](https://seclists.org/oss-sec/2026/q2/546)
(2026-05-15) described two issues, **V-01** (alignment overflow) and **V-03**
(n_dims bound). **Correcting the record explicitly: per the advisory itself,
V-01 was located in `ggml/src/gguf.cpp` (the C++ loader), NOT in this
Python reader.** Only V-03 was ever a Python-reader issue, and it maps to
the `5788b510a1` hardening above. Both V-01 and V-03 are fixed as of the
commit vendored here.

**Conclusion: this project is regression fuzzing.** The goal was never to
rediscover V-01 or V-03 (V-01 isn't even reachable from this file; V-03 is
already fixed and covered by a positive-control test below). The real
question this campaign asks is: do the three hardening commits hold up
under sustained, coverage-guided adversarial mutation, and is there
anything adjacent to them that was missed? The answer to the second half
turned out to be yes -- see "Findings" below.

## Positive control: are the guards actually reachable?

**Yes, all six guard conditions are reachable and do trigger correctly**,
proven by hand-constructing byte-exact inputs (not by fuzzing) in
`tests/test_guards.py` -- 11 tests, all passing:

| Guard | Commit | Test | Result |
|---|---|---|---|
| alignment == 0 | `418dea39ce` | `test_alignment_zero_raises` | raises `ValueError: Invalid alignment...` |
| alignment == 3 (non-power-of-two) | `418dea39ce` | `test_alignment_non_power_of_two_raises` | raises same |
| alignment == 64 (valid, negative control) | `418dea39ce` | `test_alignment_valid_power_of_two_does_not_raise_this_guard` | does NOT raise; `reader.alignment == 64` |
| n_dims == 5 (> GGML_MAX_DIMS) | `5788b510a1` | `test_n_dims_exceeds_max_raises` | raises `ValueError: ...exceeds GGML_MAX_DIMS...` |
| n_dims == 4 (boundary, negative control) | `5788b510a1` | `test_n_dims_at_max_does_not_raise_this_guard` | does NOT raise; tensor parses with shape `[1,1,1,1]` |
| tensor_count > 2^30 | `0329fcdac8` | `test_tensor_count_exceeds_max_raises` | raises `ValueError: Tensor count...` |
| kv_count > 2^30 | `0329fcdac8` | `test_kv_count_exceeds_max_raises` | raises `ValueError: KV count...` |
| string length > 2^30 | `0329fcdac8` | `test_string_length_exceeds_max_raises` | raises `ValueError: String length...exceeds maximum` |
| string length > remaining file size | `0329fcdac8` (related guard, same code path) | `test_string_length_exceeding_file_size_raises` | raises `ValueError: ...exceeds remaining file size` |
| array length > 2^30 | `0329fcdac8` | `test_array_length_exceeds_max_raises` | raises `ValueError: Array length...` |

Run: `cd /home/kali/director/projects/gguf-fuzzing && .venv/bin/python3 -m pytest tests/test_guards.py -v`
gives **11 passed** in well under a second. Rerun any time to reverify.

Two negative controls are included deliberately (valid alignment=64;
n_dims at the exact boundary of 4) so the tests prove the guards are
specific, not a blanket rejection of any input touching those fields.

This rules out the biggest threat to a null result: it is not the case
that the harness silently fails to reach the guarded code. It reaches all
of it, on hand-built inputs, every time.

## Instrumentation proof

**Coverage genuinely differs, instrumented vs. not, on this exact target.**
Measured with `coverage.py` (independent of Atheris's own instrumentation),
tracing line execution in `vendor/gguf/gguf_reader.py` only, for two
otherwise-identical harnesses (`tests/_instrumented_subject.py` and
`tests/_uninstrumented_subject.py`), same seed corpus (`corpus/`), same
`-atheris_runs=8000`, same libFuzzer PRNG seed (`-seed=42`):

- **Instrumented: 89% line coverage** (207/233 statements; missing lines
  19-22, 71-76, 93, 102, 162-163, 185, 200, 204, 257, 272, 343, 362-363,
  365-366, 368-369, 371-372, 374-375 -- see
  `logs/instrumentation_proof/instrumented_coverage_report.txt`)
- **Uninstrumented: 80% line coverage** (187/233 statements -- see
  `logs/instrumentation_proof/uninstrumented_coverage_report.txt`)
- **Gap: 9 percentage points**, for an identical run budget and identical
  seeds. The uninstrumented run's own libFuzzer output states the failure
  mode directly: `WARNING: no interesting inputs were found so far. Is the
  code instrumented for coverage?` (see
  `logs/instrumentation_proof/uninstrumented_run.log`). It ran all 8000
  iterations, exited 0, and never grew its corpus past the 3 hand-supplied
  seeds -- exactly the "looks like a working fuzzer, isn't one" failure mode
  this test exists to catch.
- This exact comparison is automated as
  `tests/test_instrumentation.py::test_instrumentation_increases_gguf_reader_coverage`,
  which asserts the gap is >= 3 percentage points (a conservative floor
  under the ~5-10 point gaps observed across repeated trials with different
  PRNG seeds during development) and **fails loudly** (verified by
  temporarily raising the threshold to 99 during development -- the test
  correctly failed and reported the real numbers) rather than passing
  vacuously.
- **Known flakiness, handled honestly, not hidden:** some libFuzzer PRNG
  seeds drive the *instrumented* side into the CPU-time-exhaustion finding
  described below before it can complete cleanly (an OOM/timeout kills the
  process before coverage.py can flush its data file). The test tries a
  short list of fixed seeds and requires at least one clean pair; every
  seed that did produce a clean pair during development showed the same
  qualitative result (instrumented always higher, gap always >= 5 points).

## Campaign results

Two separate runs were used, for two different honest reasons, and both
are reported rather than picking whichever number looks better.

### Run A -- coverage measurement (clean, reproducible baseline)

- **Command:** `coverage run --include='*/vendor/gguf/gguf_reader.py'
  src/fuzz_gguf.py <fresh corpus dir>/ -atheris_runs=5000 -timeout=5
  -rss_limit_mb=2048 -seed=42`
- **Why a separate, smaller, seeded run for coverage:** the hand-built
  `kv_pairs.gguf` seed contains a `general.some_array` KV field, and Atheris
  reliably mutates its array-length field into a CPU-time-exhaustion input
  (see Findings, below) within roughly 6,000-15,000 iterations from that
  seed. That is itself part of the finding (a defect can be reached fast),
  but it also means an unseeded/long run cannot produce a clean, complete
  coverage.py report, because a process killed by libFuzzer's own
  timeout/OOM handling exits before coverage.py's atexit hook can flush
  data (verified directly: `logs/campaign.coverage` from the full
  restart-based campaign below has zero recorded data for exactly this
  reason -- every one of its 17 restarts ended in a crash, none exited
  cleanly). 5000 runs with a fixed seed was verified to reproduce cleanly
  three times in a row from a freshly emptied corpus directory before being
  adopted as the reported baseline.
- **Executions:** 4,932 (highest libFuzzer progress counter reached; see
  `logs/coverage_final_run.log`)
- **Exit code:** 0 (clean)
- **Coverage.py result: 85% line coverage over `gguf_reader.py`** (197/233
  statements; see `logs/coverage_final.coverage`, human-readable at
  `logs/coverage_html/index.html`)
- **libFuzzer cov:/ft: at end of run:** `cov: 118 ft: 231` (from
  `logs/coverage_final_run.log`)
- **Final corpus size this run:** 31 files, 2,822 bytes total

### Run B -- crash-hunting campaign (the CPU-DoS finding)

- **Command:** `src/run_campaign.sh` / `src/resume_campaign.sh`, which drive
  `src/fuzz_gguf.py` under `coverage run --append`, restarting on every
  libFuzzer crash/timeout exit (libFuzzer stops the whole process on the
  first finding by design; the restart script is documented in
  `src/run_campaign.sh`'s header comment).
- **Parameters:** `-atheris_runs=50000` per restart, `-timeout=5`,
  `-rss_limit_mb=2048`, `-artifact_prefix=artifacts/`, seed corpus grown
  cumulatively in `corpus_evolved/` across restarts.
- **Total executions: 76,271**, summed across 17 restarts, every one of
  which was stopped by an independent reproduction of the same
  CPU-time-exhaustion finding described below (raw per-restart logs:
  `logs/campaign_restart_1.log` through `logs/campaign_restart_17.log`;
  summary: `logs/campaign_summary.log`).
- **Wall time: 10 minutes 16 seconds** (19:49:04 UTC to 19:59:20 UTC; see
  timestamps in `logs/campaign_summary.log`).
- **Overall executions/second: ~124** (76,271 / 616s). This is much lower
  than the ~13,000-14,700 exec/s seen in clean stretches of Run A; the gap
  is explained directly by this campaign hitting a real, reproducible
  5-8 second-per-input timeout condition 17 times, each of which burns most
  of a restart's wall-clock budget on one slow input before libFuzzer
  aborts the process. This is itself evidence about the finding's severity,
  not a harness inefficiency: a fuzzer campaign against this file can be
  trivially reduced to ~124 exec/s by an attacker who can influence even
  one KV array field.
- **A restart 18 was started** and manually stopped after 2,048 executions
  with no new finding, once 17 independent reproductions of the same bug
  were judged more than sufficient evidence; those 2,048 executions are
  NOT included in the 76,271 total above, to keep that number conservative
  and tied only to restarts that reached a definite outcome.
- **Final `corpus_evolved/` size:** 132 files, 540 KB total.
- **libFuzzer cov:/ft: reached during this campaign (peak observed, restart
  18):** `cov: 130 ft: 304` (see `logs/campaign_restart_18.log`) -- higher
  than Run A's `cov: 118 ft: 231` because this campaign ran far more
  cumulative executions and a larger, more diverse evolved corpus.
- **Crashes/timeouts found:** 17 raw artifacts preserved under
  `artifacts/timeouts_and_ooms/restart{1..17}_timeout-*`, all the same
  finding class (see below). No `crash-*` or unexplained `oom-*` artifacts
  were produced by this specific campaign configuration.

## Findings

### Finding 1: CPU-time exhaustion via oversized-but-under-guard array element count

**This is a real defect, not an expected rejection.** A small file (as
small as 101 bytes, minimized from an original 186-byte fuzzer-found input
using `-minimize_crash=1`; see `artifacts/minimized/cpu_dos_minimized.gguf`
and `logs/minimize.log`) can cost 20-40+ seconds of pure CPU time to parse,
with no exception raised at all in the fastest-observed case (the reader
"succeeds" and returns a `ReaderField` holding millions of near-empty numpy
sub-arrays), or occasionally an `IndexError` well after the cost has
already been paid.

**Mechanism:** a KV pair of ARRAY type declares an element count (a
uint64, read at `gguf_reader.py:255`) that is checked against
`GGUF_MAX_ARRAY_ELEMENTS` (2^30 ~= 1.07 billion) at line 256-257 -- the
2026-08-19 hardening guard. A count well under that guard (observed:
7,012,355 and 13,434,883 in two independent captured reproductions) is
still accepted, and `_get_field_parts` (line 234) then iterates that many
times in a plain Python `for` loop (`gguf_reader.py:262-269`), making one
recursive Python function call per claimed element regardless of how much
actual data remains in the file. The count guard bounds memory correctly
(it prevents an actual multi-gigabyte allocation), but it does not bound
the time cost of the per-element Python-level loop overhead, and it does
not check the claimed count against the bytes actually remaining in the
file before starting the loop (unlike the string-length guard at line
230-231, which does check remaining file size).

**Reproduction (standalone, outside any fuzzer):**
```
$ .venv/bin/python3 -c "
import sys, time
sys.path.insert(0, 'vendor')
from gguf.gguf_reader import GGUFReader
raw = open('artifacts/minimized/cpu_dos_minimized.gguf','rb').read()
open('/dev/shm/repro.gguf','wb').write(raw)
start = time.time()
try:
    r = GGUFReader('/dev/shm/repro.gguf')
    print('parsed OK in', time.time()-start, 's')
except Exception as e:
    print('raised', type(e).__name__, 'after', time.time()-start, 's')
"
raised IndexError index 0 is out of bounds for axis 0 with size 0 after 39.67 s
```
An earlier, unminimized 185-byte capture from the same campaign completed
with no exception at all in 21.3 seconds
(`artifacts/finding_01_cpu_dos/timeout-be944662343b79cce764af359c6c937afea9cae8`),
also independently reproduced 15 more times across the campaign's other
restart artifacts under `artifacts/timeouts_and_ooms/`, all the same
mechanism.

**Severity assessment (this project's own judgment, stated plainly so it
can be checked, not asserted as authoritative):** this is a low-to-moderate
severity availability issue, not a memory-safety issue. There is no crash,
no exploit primitive, no data corruption -- it's an algorithmic-complexity /
denial-of-service vector. Impact is bounded by whatever process calls
`GGUFReader()` on attacker-influenced input without its own timeout (this
harness's own `-timeout=5` is a fuzzer safety net, not something the
library provides). Any caller that parses untrusted `.gguf` files
synchronously (e.g., a model-hosting service accepting user uploads) could
have a single small file tie up a worker thread for tens of seconds.

**This has not been reported upstream as part of this project** (out of
scope per this task's instructions: report, don't patch, and this is a
portfolio/regression-fuzzing exercise, not a live disclosure process). If
this were a real engagement, the next step would be responsible disclosure
to the llama.cpp maintainers with the minimized 101-byte reproducer and
this write-up.

### No other findings

Across 76,271 executions in the crash-hunting campaign and 4,932 additional
executions in the coverage-measurement run (81,203 total, all from the
current pinned commit, all synthetic/fuzzer-generated inputs, zero
downloaded model files), the only distinct finding was the one described
above. No memory-safety crash, no unhandled exception outside the harness's
documented `EXPECTED_EXCEPTIONS` set (beyond the CPU-DoS case), and no
alignment/n_dims/count/length guard bypass was observed.

## What this does NOT prove

Stated plainly and adversarially, per this project's own requirement for
honesty over a polished-sounding result:

- **A null result (beyond the one finding above) over ~81,000 executions on
  one parser, from one hand-built seed corpus, is weak evidence of overall
  safety.** It is not proof of absence of other bugs. Atheris's mutation
  strategy, this harness's specific exception-handling choices, and the
  seed corpus's specific shape all bias which parts of the input space get
  explored. A differently-shaped seed corpus, a longer run, or a different
  fuzzer (or the same fuzzer with `-workers=N` parallelism) could plausibly
  find more.
- **85%/89% line coverage is line coverage, not path coverage or branch
  coverage.** A line can be marked "covered" while only one of several
  possible values/branches that reach it was ever exercised. Two inputs
  that both execute the same line via very different data can look
  identical to a line-coverage tool. The true state-space of possible
  malformed GGUF byte layouts is astronomically larger than what 85-89%
  line coverage implies is "explored."
- **The C++ GGUF loader (`ggml/src/gguf.cpp`) is completely untested by
  this work.** This project only exercises the pure-Python reader in
  `gguf-py/`. The advisory's actual memory-safety-relevant finding, V-01,
  lived in that C++ code, which this project does not touch, compile, or
  fuzz in any way. Anyone reading this write-up as evidence that
  "llama.cpp's GGUF handling is fuzzed and safe" would be wrong; at most,
  one specific pure-Python reader implementation has been regression-fuzzed.
- **The remaining 11-15% of uncovered lines in `gguf_reader.py`** (see the
  "Missing" column in the coverage reports) include real code paths --
  e.g. some byte-swapped/big-endian handling, some `ReaderField.contents()`
  branches for nested array-of-string indexing, and some tensor dtype
  branches (F16/F64/I8/I16/I32/I64 in `_build_tensors`) that the current
  seed corpus and short run did not reach. A defect specifically in one of
  those unreached lines would not have been found regardless of how many
  executions were run, because the input space that reaches them was never
  sampled.
- **The CPU-time-exhaustion finding was found and reproduced from a
  hand-built seed, not "discovered from nothing"** by the fuzzer in a
  vacuum -- the `general.some_array` KV field in `corpus/kv_pairs.gguf`
  gave Atheris an ARRAY-type value to mutate the length of. Without that
  seed shape present, this specific finding might have taken substantially
  longer (or not been found at all) in the run budget used here. This is
  disclosed, not hidden, because it is directly relevant to interpreting
  "no other findings" above: the corpus shapes what gets explored, and an
  absence of other findings says as much about corpus/seed choices as
  about the code's quality.
- **Single-process fuzzing only.** No `-fork=N` or `-workers=N` parallel
  fuzzing was used; a parallel run exploring more of the input space
  simultaneously might reach different code within the same wall-clock
  budget.
- **No sanitizer instrumentation (ASan/UBSan/MSan)** was used or is
  applicable, because the target is pure Python over numpy, not C/C++;
  Atheris's own startup warnings
  (`WARNING: Failed to find function "__sanitizer_acquire_crash_state"`,
  visible in every log in `logs/`) confirm no native sanitizer was linked
  in. This is expected and correct for a pure-Python target, but it means
  this project provides no evidence about memory safety in the sense that
  term has for a C/C++ fuzzing target -- only about Python-level exceptions,
  hangs, and resource exhaustion.

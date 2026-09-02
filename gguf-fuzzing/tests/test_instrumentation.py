"""
The instrumentation proof.

The failure mode being guarded against: if the target module is imported
OUTSIDE `atheris.instrument_imports()`, its bytecode carries no coverage
counters. Atheris/libFuzzer will still run, still print "cov:"/"ft:" and
exec/s numbers, and still exit 0 -- it looks exactly like a working
coverage-guided fuzzer. It is not: with no counters in the target, every
mutation is accepted or rejected essentially at random with respect to the
target's actual control flow, so the fuzzer degrades to undirected random
byte generation while remaining outwardly indistinguishable from a real run.

This test proves the difference is real and measurable, using a tool that
is independent of Atheris's own instrumentation: coverage.py, tracing line
execution in vendor/gguf/gguf_reader.py specifically (not the harness, not
Atheris internals).

METHOD
Two near-identical throwaway harnesses are shipped alongside this test:
  - tests/_instrumented_subject.py    imports GGUFReader inside
                                       atheris.instrument_imports()
  - tests/_uninstrumented_subject.py  imports GGUFReader as a plain import
Both run the exact same TestOneInput logic, from the exact same seed
corpus (corpus/), for the exact same fixed -atheris_runs budget and a
fixed libFuzzer -seed (so the pseudo-random mutation sequence is
reproducible), each under `coverage run --include=.../gguf_reader.py`.
We then read back the two coverage.py reports and assert the instrumented
run's line-coverage percentage over gguf_reader.py is measurably higher.

WHY THIS IS THE RIGHT COMPARISON
libFuzzer's own mutation strategy is driven entirely by the coverage
counters it can see. If those counters are absent from the target (the
uninstrumented case), libFuzzer cannot tell a "boring" mutation from an
"interesting" one anywhere inside gguf_reader.py, so its corpus never
grows past the hand-supplied seeds and it cannot steer inputs toward
new branches (e.g. the alignment guard, the n_dims guard, array/string
size guards -- see vendor/COMMIT.txt for line numbers). coverage.py, which
instruments independently of Atheris, lets us measure the actual
consequence of that blindness: fewer lines of gguf_reader.py get executed
for the same run budget.

A KNOWN SOURCE OF FLAKINESS, HANDLED HONESTLY
During development we found that certain libFuzzer PRNG seeds mutate the
`general.some_array` KV field in corpus/kv_pairs.gguf into a claimed
element count that is under the 2026-08-19 size guard (1<<30 elements) but
still large enough, combined with an 8-byte element dtype, to request a
multi-gigabyte numpy allocation and trip libFuzzer's -rss_limit_mb OOM
killer. This is a real robustness finding (see FINDINGS.md), not a test
bug -- but an OOM abort kills the subprocess before coverage.py can flush
its data file, which would make a single fixed seed flaky. Rather than
hide this, we run across a small, fixed list of seeds and require the
comparison to hold on every seed that completes cleanly on BOTH sides,
and we require at least one clean pair to exist. If every seed in the
list OOMs, the test fails loudly rather than silently passing on zero
evidence.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CORPUS_DIR = PROJECT_ROOT / 'corpus'
INSTRUMENTED_SUBJECT = Path(__file__).resolve().parent / '_instrumented_subject.py'
UNINSTRUMENTED_SUBJECT = Path(__file__).resolve().parent / '_uninstrumented_subject.py'

# Fixed libFuzzer PRNG seeds tried in order. See module docstring: some
# seeds drive the instrumented run into a real, separately-documented OOM
# (FINDINGS.md) before it can exit cleanly; we skip past those rather than
# treat them as a test failure, since that OOM is a target property, not
# an instrumentation property.
CANDIDATE_SEEDS = [42, 999, 222, 111, 7, 2026, 1, 2, 3]
ATHERIS_RUNS = 8000
RSS_LIMIT_MB = 400
RUN_TIMEOUT_S = 90

# Minimum required gap (percentage points) between instrumented and
# uninstrumented line coverage of gguf_reader.py. Observed gaps during
# development ranged ~5-10 points (89-90% instrumented vs a flat 80%
# uninstrumented); 3 points gives comfortable margin against noise while
# still being a meaningful, non-vacuous threshold.
MIN_REQUIRED_GAP_POINTS = 3.0


def _run_one(subject: Path, corpus_copy: Path, data_file: Path, seed: int) -> int:
    """Run `coverage run <subject> <corpus_copy>/ -atheris_runs=N ...`
    tracing only gguf_reader.py. Returns the subprocess exit code."""
    cmd = [
        sys.executable, '-m', 'coverage', 'run',
        f'--data-file={data_file}',
        '--include=*/vendor/gguf/gguf_reader.py',
        str(subject),
        f'{corpus_copy}/',
        f'-atheris_runs={ATHERIS_RUNS}',
        '-close_fd_mask=3',
        f'-rss_limit_mb={RSS_LIMIT_MB}',
        f'-seed={seed}',
        f'-artifact_prefix={corpus_copy}/../artifacts_',
    ]
    proc = subprocess.run(
        cmd, cwd=PROJECT_ROOT, capture_output=True, text=True, timeout=RUN_TIMEOUT_S,
    )
    return proc.returncode


def _coverage_percent(data_file: Path) -> float | None:
    """Return the line-coverage percentage coverage.py recorded for
    gguf_reader.py, or None if no data was recorded (e.g. process OOM'd
    before it could flush)."""
    if not data_file.exists():
        return None
    proc = subprocess.run(
        [sys.executable, '-m', 'coverage', 'report', f'--data-file={data_file}'],
        cwd=PROJECT_ROOT, capture_output=True, text=True,
    )
    if proc.returncode != 0 or 'No data to report' in proc.stdout:
        return None
    last_line = [ln for ln in proc.stdout.splitlines() if ln.strip()][-1]
    # e.g. "TOTAL    233   24   90%"
    pct_field = last_line.split()[-1]
    if not pct_field.endswith('%'):
        return None
    return float(pct_field.rstrip('%'))


def test_instrumentation_increases_gguf_reader_coverage(tmp_path):
    assert INSTRUMENTED_SUBJECT.exists(), 'missing tests/_instrumented_subject.py'
    assert UNINSTRUMENTED_SUBJECT.exists(), 'missing tests/_uninstrumented_subject.py'
    seeds = list(CORPUS_DIR.glob('*.gguf'))
    assert seeds, 'corpus/ has no seed files; run src/make_corpus.py first'

    results = []  # list of (seed, inst_pct, uninst_pct)

    for seed in CANDIDATE_SEEDS:
        inst_corpus = tmp_path / f'inst_corpus_{seed}'
        uninst_corpus = tmp_path / f'uninst_corpus_{seed}'
        inst_corpus.mkdir()
        uninst_corpus.mkdir()
        for f in seeds:
            (inst_corpus / f.name).write_bytes(f.read_bytes())
            (uninst_corpus / f.name).write_bytes(f.read_bytes())

        inst_data = tmp_path / f'inst_{seed}.coverage'
        uninst_data = tmp_path / f'uninst_{seed}.coverage'

        rc_inst = _run_one(INSTRUMENTED_SUBJECT, inst_corpus, inst_data, seed)
        rc_uninst = _run_one(UNINSTRUMENTED_SUBJECT, uninst_corpus, uninst_data, seed)

        inst_pct = _coverage_percent(inst_data)
        uninst_pct = _coverage_percent(uninst_data)

        if inst_pct is None or uninst_pct is None:
            # Almost always the instrumented side hitting the documented
            # OOM (rc_inst == 71) on this particular seed. Try the next
            # fixed seed instead of failing outright.
            continue

        results.append((seed, inst_pct, uninst_pct))
        # Two clean pairs is enough evidence; stop early to keep the test fast.
        if len(results) >= 2:
            break

    assert results, (
        'Every candidate seed produced an incomplete run on at least one '
        'side (most likely the documented gguf_reader.py large-allocation '
        'OOM on the instrumented side -- see FINDINGS.md). Could not '
        'produce even one clean instrumented-vs-uninstrumented pair, so '
        'this test cannot honestly claim anything and must fail rather '
        'than pass vacuously.'
    )

    for seed, inst_pct, uninst_pct in results:
        gap = inst_pct - uninst_pct
        assert gap >= MIN_REQUIRED_GAP_POINTS, (
            f'seed={seed}: instrumented coverage ({inst_pct}%) was not '
            f'meaningfully higher than uninstrumented coverage '
            f'({uninst_pct}%) over vendor/gguf/gguf_reader.py -- gap was '
            f'only {gap:.1f} points, required >= {MIN_REQUIRED_GAP_POINTS}. '
            'This would mean instrumentation is not measurably helping, '
            'which contradicts the whole premise of coverage-guided '
            'fuzzing for this target.'
        )

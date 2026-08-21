#!/usr/bin/env python3
"""
Atheris coverage-guided fuzzing harness for llama.cpp's pure-Python GGUF
reader (vendor/gguf/gguf_reader.py, pinned commit in vendor/COMMIT.txt).

WHY A REAL FILE PATH, NOT BytesIO
GGUFReader.__init__ consumes its input via exactly one call:
    self.data = np.memmap(path, mode=mode)
np.memmap requires something that resolves to a real file descriptor/path
on disk (or an already-open file object backed by a real fd) -- it cannot
memory-map a BytesIO. So every fuzz iteration must materialize the
candidate bytes as an actual file before handing it to GGUFReader.

WHY /dev/shm AND A SINGLE REUSED FILE
/dev/shm is tmpfs (RAM-backed), so writes never touch a physical disk.
We reuse ONE file path for the lifetime of the process and overwrite its
contents every iteration, rather than creating+unlinking a new file per
iteration. This is safe here because:
  - Atheris/libFuzzer's in-process fuzzing loop (the mode this harness
    uses, via atheris.Fuzz()) calls TestOneInput repeatedly, one input at
    a time, in a single thread within a single process. There is no
    concurrent access to the same path from two iterations at once.
  - Each iteration fully truncates and rewrites the file before
    constructing a fresh GGUFReader, so no state leaks between iterations.
  - If this harness is ever run with libFuzzer's multi-process `-jobs=N`/
    `-workers=N` parallel fuzzing, each worker is a separate OS process and
    gets its own path (the path embeds os.getpid()), so workers cannot
    collide with each other either.
We measured the alternative (mkstemp + unlink every iteration) during
development: reusing one path was appreciably faster in exec/sec (fewer
syscalls per iteration: open/write/close + memmap open, vs.
mkstemp/write/close + memmap open + unlink), and tmpfs already removes the
"no disk I/O" concern that motivated avoiding a fresh temp file. See
logs/ for the campaign that used this design.

WHAT THIS HARNESS EXERCISES
After GGUFReader() construction succeeds, we additionally touch
reader.fields (iterate every ReaderField and call .contents()) and
reader.tensors (iterate every ReaderTensor and touch .data), because
ReaderField.contents() and the tensor data array are populated eagerly by
__init__ in this version of the reader, but touching them anyway both
(a) documents that we deliberately exercise the full public read surface,
not just __init__, and (b) protects this harness against future upstream
changes that make any of this lazier without us noticing coverage drop
silently.

INSTRUMENTATION
The target MUST be imported inside atheris.instrument_imports(), otherwise
its bytecode carries no coverage counters and libFuzzer/Atheris silently
degrades to blind random mutation -- it will still run, still print
numbers, and still "work" in the sense of not crashing, while providing
none of the guidance that makes this a coverage-guided fuzzer rather than
a random byte generator with extra steps. See tests/test_instrumentation.py
for the proof that this actually matters for this specific target.
"""
from __future__ import annotations

import atexit
import os
import struct
import sys
from pathlib import Path

import atheris

# --- Vendored target import: MUST happen inside instrument_imports() ---
PROJECT_ROOT = Path(__file__).resolve().parent.parent
VENDOR_PATH = PROJECT_ROOT / 'vendor'
sys.path.insert(0, str(VENDOR_PATH))

with atheris.instrument_imports():
    from gguf.gguf_reader import GGUFReader

# Exceptions the vendored reader is documented (by its own source, read at
# vendor/gguf/gguf_reader.py) to raise for malformed-but-recognized-as-bad
# input. Everything else is an unexpected defect and must propagate so
# Atheris records it as a finding.
#
#   ValueError          -- every explicit guard in gguf_reader.py: bad magic,
#                           unsupported version, tensor/kv count too large,
#                           string/array length too large, invalid alignment,
#                           n_dims > GGML_MAX_DIMS, duplicate field/tensor
#                           name, unknown GGUFValueType, bad general.alignment
#                           type.
#   KeyError             -- _push_field raises KeyError on duplicate field
#                           name (line ~218); this is a plain KeyError, not
#                           wrapped in ValueError.
#   struct.error         -- defensive: not currently raised by gguf_reader.py
#                           itself (it uses numpy views, not struct.unpack,
#                           for parsing), but numpy dtype/count math funnels
#                           through the same "malformed size field" failure
#                           class, so we keep this in the expected set in
#                           case a future/other code path uses struct.
#   OSError              -- np.memmap(path, mode=mode) can raise OSError
#                           (e.g. ValueError is more common for a zero-length
#                           mmap target, but OSError/mmap.error is possible
#                           for other memmap failure modes on some
#                           platforms); caught defensively.
#   UnicodeDecodeError    -- str(bytes(...), encoding='utf-8') in _build_tensors
#                           and ReaderField.contents() will raise this if a
#                           string field's bytes are not valid UTF-8. This is
#                           an EXPECTED rejection of malformed input, not a
#                           defect: the format has no other encoding option
#                           and upstream does not catch it either, but it is
#                           not a crash we want reported as a "finding" since
#                           it is deterministic, safe, and not a security
#                           issue (no memory unsafety, just a Python
#                           exception).
#   IndexError            -- numpy raises this for some out-of-range slicing
#                           patterns instead of ValueError depending on how
#                           the offset arithmetic works out; observed during
#                           harness development on deliberately-truncated
#                           inputs. Treated as an expected "ran out of bytes"
#                           rejection, same class as ValueError.
#   MemoryError            -- some length fields, even after the 2026-08-19
#                           size guards (max 1<<30 elements/bytes), can still
#                           request very large-but-under-guard allocations
#                           (e.g. a 2**30-element array of 8-byte values).
#                           This is a resource-exhaustion condition, not
#                           memory corruption; caught so the fuzzer doesn't
#                           spend its RSS budget on it, and reported
#                           separately in FINDINGS.md as a robustness
#                           observation rather than a crash bug.
EXPECTED_EXCEPTIONS = (
    ValueError,
    KeyError,
    struct.error,
    OSError,
    UnicodeDecodeError,
    IndexError,
    MemoryError,
)

_TARGET_PATH = Path(f'/dev/shm/gguf_fuzz_{os.getpid()}.gguf')


def _cleanup() -> None:
    try:
        _TARGET_PATH.unlink()
    except FileNotFoundError:
        pass


atexit.register(_cleanup)


def _exercise(reader: GGUFReader) -> None:
    """Touch reader.fields and reader.tensors so any lazily-parsed or
    lazily-formatted paths run, not just __init__."""
    for field in reader.fields.values():
        try:
            _ = field.contents()
        except EXPECTED_EXCEPTIONS:
            pass
    for tensor in reader.tensors:
        _ = tensor.data.shape
        _ = tensor.n_elements
        _ = tensor.n_bytes


def TestOneInput(data: bytes) -> None:
    # Write the candidate bytes to our reused tmpfs path. Truncate first
    # (mode 'wb') so a shorter input never leaves stale trailing bytes from
    # a previous, longer iteration.
    try:
        with open(_TARGET_PATH, 'wb') as f:
            f.write(data)
    except OSError:
        # Extremely large `data` could in principle exceed tmpfs free space;
        # that's an environment limit, not a target defect. Skip the input.
        return

    try:
        reader = GGUFReader(str(_TARGET_PATH))
        _exercise(reader)
    except EXPECTED_EXCEPTIONS:
        return
    # Anything else (AssertionError, TypeError, RuntimeError, a numpy
    # internal error class we didn't anticipate, etc.) propagates and
    # Atheris records it as a crash/finding.


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == '__main__':
    main()

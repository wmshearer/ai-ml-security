#!/usr/bin/env python3
"""
Minimal Atheris harness used ONLY by tests/test_instrumentation.py as the
"negative" (uninstrumented) side of the instrumented-vs-uninstrumented
coverage comparison. Identical to _instrumented_subject.py except the
target import happens as a PLAIN import, outside
atheris.instrument_imports(). This reproduces the failure mode the test
exists to catch: a fuzzer that runs, reports numbers, and exits 0, while
carrying no coverage counters for the code it's actually exercising.
"""
from __future__ import annotations

import atexit
import os
import struct
import sys
from pathlib import Path

import atheris

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / 'vendor'))

# Deliberately NOT wrapped in atheris.instrument_imports(). This is the
# negative case the test is designed to detect.
from gguf.gguf_reader import GGUFReader

EXPECTED_EXCEPTIONS = (
    ValueError, KeyError, struct.error, OSError, UnicodeDecodeError,
    IndexError, MemoryError,
)

_TARGET_PATH = Path(f'/dev/shm/gguf_instr_test_uninst_{os.getpid()}.gguf')
atexit.register(lambda: _TARGET_PATH.unlink(missing_ok=True))


def TestOneInput(data: bytes) -> None:
    try:
        with open(_TARGET_PATH, 'wb') as f:
            f.write(data)
        reader = GGUFReader(str(_TARGET_PATH))
        for field in reader.fields.values():
            try:
                field.contents()
            except EXPECTED_EXCEPTIONS:
                pass
        for tensor in reader.tensors:
            _ = tensor.data.shape
    except EXPECTED_EXCEPTIONS:
        return


if __name__ == '__main__':
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()

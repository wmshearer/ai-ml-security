#!/usr/bin/env python3
"""
Minimal Atheris harness used ONLY by tests/test_instrumentation.py as the
"positive" (instrumented) side of the instrumented-vs-uninstrumented
coverage comparison. Not the main fuzzing harness -- see src/fuzz_gguf.py
for that. Kept deliberately close to src/fuzz_gguf.py's TestOneInput logic
so the comparison is apples-to-apples, but trimmed to the essentials.
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

with atheris.instrument_imports():
    from gguf.gguf_reader import GGUFReader

EXPECTED_EXCEPTIONS = (
    ValueError, KeyError, struct.error, OSError, UnicodeDecodeError,
    IndexError, MemoryError,
)

_TARGET_PATH = Path(f'/dev/shm/gguf_instr_test_inst_{os.getpid()}.gguf')
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

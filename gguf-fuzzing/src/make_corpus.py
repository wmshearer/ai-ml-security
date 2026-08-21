#!/usr/bin/env python3
"""
Corpus builder for the GGUF fuzzing project.

Atheris (like any coverage-guided fuzzer) starts from a corpus of seed
inputs and mutates them. A fuzzer with no valid seeds spends nearly all of
its budget failing the first 4-byte magic-number check in GGUFReader.__init__
and never reaches the interesting parsing logic (KV pairs, tensor info,
alignment, array handling). This script hand-builds several MINIMAL, VALID
GGUF files by encoding the exact byte layout that vendor/gguf/gguf_reader.py
expects, then verifies each one actually parses through the vendored
GGUFReader with no exception before writing it to corpus/.

The byte layout below is derived directly from reading
vendor/gguf/gguf_reader.py (not from external docs or guessing):

  Header (see GGUFReader.__init__, lines ~137-178):
    uint32  magic          -- must equal GGUF_MAGIC ("GGUF" as little-endian
                              bytes 0x47475546, checked as uint32 against
                              constants.GGUF_MAGIC = 0x46554747)
    uint32  version        -- must be in READER_SUPPORTED_VERSIONS = [2, 3]
    uint64  tensor_count
    uint64  kv_count

  KV pairs (see _build_fields at line ~306, _get_field_parts at line ~234):
    For each of kv_count entries:
      string  key            -- see _get_str at line ~226: uint64 length,
                                 then that many raw bytes (no NUL terminator)
      uint32  value_type      -- one of GGUFValueType (constants.py)
      <value> -- shape depends on value_type:
        scalar types (UINT8/INT8/UINT16/INT16/UINT32/INT32/FLOAT32/UINT64/
        INT64/FLOAT64/BOOL): raw bytes of that numpy dtype, native size
        STRING: same string encoding as key (uint64 length + bytes)
        ARRAY: uint32 element_type, uint64 element_count, then that many
               values of element_type back-to-back (arrays of arrays are
               technically supported by the recursive parser but we do not
               need that for seeds)

  Tensor info (see _build_tensor_info / _get_tensor_info_field, line ~274):
    For each of tensor_count entries:
      string   name
      uint32   n_dims          -- must be <= GGML_MAX_DIMS (4)
      uint64[] dims             -- n_dims of them
      uint32   dtype            -- GGMLQuantizationType value (0 = F32)
      uint64   offset           -- offset of tensor data, relative to the
                                   (alignment-padded) start of the tensor
                                   data block

  Then padding to `alignment` (default GGUF_DEFAULT_ALIGNMENT = 32, or
  overridden by a general.alignment UINT32 KV field, which must be a
  non-zero power of two per the 2026-02-24 hardening commit), then raw
  tensor data bytes.

All integers are little-endian (host byte order on the machines this is
built and fuzzed on; GGUFReader auto-detects byte-swapped files by checking
whether the low 16 bits of the version field are zero, but we don't need
that path for seeds -- the harness/fuzzer can discover it by mutation).
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

GGUF_MAGIC = 0x46554747  # matches constants.GGUF_MAGIC; little-endian bytes spell "GGUF"
GGUF_VERSION = 3

# GGUFValueType values (see vendor/gguf/constants.py)
VT_UINT8, VT_INT8 = 0, 1
VT_UINT16, VT_INT16 = 2, 3
VT_UINT32, VT_INT32 = 4, 5
VT_FLOAT32 = 6
VT_BOOL = 7
VT_STRING = 8
VT_ARRAY = 9
VT_UINT64, VT_INT64 = 10, 11
VT_FLOAT64 = 12

# GGMLQuantizationType.F32 = 0 (see vendor/gguf/constants.py)
GGML_TYPE_F32 = 0


def u32(v: int) -> bytes:
    return struct.pack('<I', v)


def u64(v: int) -> bytes:
    return struct.pack('<Q', v)


def gguf_string(s: str) -> bytes:
    """Encode a GGUF string: uint64 length + raw utf-8 bytes, no terminator."""
    b = s.encode('utf-8')
    return u64(len(b)) + b


def kv_scalar(key: str, value_type: int, packed_value: bytes) -> bytes:
    return gguf_string(key) + u32(value_type) + packed_value


def build_header(tensor_count: int, kv_count: int, version: int = GGUF_VERSION) -> bytes:
    return u32(GGUF_MAGIC) + u32(version) + u64(tensor_count) + u64(kv_count)


def build_minimal_valid() -> bytes:
    """0 tensors, 0 KV pairs. The absolute smallest file GGUFReader will accept."""
    return build_header(tensor_count=0, kv_count=0)


def build_with_kv_pairs() -> bytes:
    """0 tensors, several KV pairs covering different GGUFValueType branches:
    a scalar uint32, a scalar float32, a string, and an array of uint8.
    Exercises _get_field_parts's scalar/string/array branches (lines ~246-270)."""
    kvs = b''
    kvs += kv_scalar('general.file_type', VT_UINT32, u32(1))
    kvs += kv_scalar('general.some_float', VT_FLOAT32, struct.pack('<f', 3.25))
    kvs += kv_scalar('general.name', VT_STRING, gguf_string('corpus-seed-model'))
    # Array of 3 uint8 values: uint32 elem_type, uint64 elem_count, then elements.
    arr_body = u32(VT_UINT8) + u64(3) + bytes([1, 2, 3])
    kvs += gguf_string('general.some_array') + u32(VT_ARRAY) + arr_body
    return build_header(tensor_count=0, kv_count=4) + kvs


def build_with_tensor() -> bytes:
    """1 KV pair (general.alignment, explicit default value) + 1 tensor
    (F32, 2 dims, 2x3 = 6 elements = 24 bytes), with real tensor data bytes
    appended after alignment padding. Exercises _build_tensor_info,
    _get_tensor_info_field, and _build_tensors (including the F32 data
    read and reshape at the end of the file)."""
    alignment = 32
    kv_count = 1
    tensor_count = 1

    kvs = kv_scalar('general.alignment', VT_UINT32, u32(alignment))

    tensor_name = 'blk.0.weight'
    n_dims = 2
    dims = [2, 3]  # 6 elements total
    tensor_info = (
        gguf_string(tensor_name)
        + u32(n_dims)
        + b''.join(u64(d) for d in dims)
        + u32(GGML_TYPE_F32)
        + u64(0)  # data_offset, relative to (padded) tensor-data start
    )

    header = build_header(tensor_count=tensor_count, kv_count=kv_count)
    pre_data = header + kvs + tensor_info

    # Pad to `alignment` as GGUFReader does: padding = offs % alignment
    padding_needed = (-len(pre_data)) % alignment
    padded = pre_data + b'\x00' * padding_needed

    # 6 float32 elements of tensor data
    tensor_data = struct.pack('<6f', 1.0, 2.0, 3.0, 4.0, 5.0, 6.0)

    return padded + tensor_data


def verify_parses(raw: bytes, tmp_path: Path, vendor_path: Path) -> None:
    """Write raw bytes to a real file and parse them with the vendored
    GGUFReader, raising if parsing fails. A corpus seed that doesn't parse
    is worse than useless: it would mean the byte layout above is wrong
    and every seed derived from it is garbage."""
    sys.path.insert(0, str(vendor_path))
    # Import lazily/once; safe to re-import on repeat calls (cached in sys.modules).
    from gguf.gguf_reader import GGUFReader  # noqa: PLC0415

    tmp_path.write_bytes(raw)
    reader = GGUFReader(str(tmp_path))
    # Touch lazily-populated attributes to make sure nothing blows up later.
    _ = list(reader.fields.items())
    _ = list(reader.tensors)


def main() -> int:
    project_root = Path(__file__).resolve().parent.parent
    vendor_path = project_root / 'vendor'
    corpus_dir = project_root / 'corpus'
    corpus_dir.mkdir(exist_ok=True)

    verify_scratch = project_root / '.corpus_verify_scratch.gguf'

    seeds = {
        'minimal_valid.gguf': build_minimal_valid(),
        'kv_pairs.gguf': build_with_kv_pairs(),
        'with_tensor.gguf': build_with_tensor(),
    }

    written = []
    for name, raw in seeds.items():
        try:
            verify_parses(raw, verify_scratch, vendor_path)
        except Exception as e:
            print(f'FAIL: seed {name} did NOT parse cleanly: {type(e).__name__}: {e}', file=sys.stderr)
            return 1
        out_path = corpus_dir / name
        out_path.write_bytes(raw)
        written.append((name, len(raw)))
        print(f'OK: {name} ({len(raw)} bytes) verified and written to {out_path}')

    if verify_scratch.exists():
        verify_scratch.unlink()

    print(f'\n{len(written)} seeds written to {corpus_dir}')
    for name, size in written:
        print(f'  {name}: {size} bytes')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

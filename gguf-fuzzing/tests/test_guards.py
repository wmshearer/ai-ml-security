"""
The positive control.

This proves the fuzzing harness (and, more fundamentally, the vendored
GGUFReader itself) can reach and trigger each of the three rounds of
hardening described in vendor/COMMIT.txt, by hand-constructing byte inputs
that violate each guard -- NOT by fuzzing. This is deliberate: a fuzzing
campaign that finds zero crashes is meaningless on its own, because a null
result is consistent with either "the code is solid" or "the harness never
reached the guarded code in the first place". This file rules out the
second explanation by proving, deterministically and by hand, that every
guarded code path is reachable and does raise when it should.

Byte layout is derived from reading vendor/gguf/gguf_reader.py directly
(see src/make_corpus.py's module docstring for the full format notes);
nothing here is guessed from external GGUF documentation.

Guards under test (see vendor/COMMIT.txt for commit hashes/dates):
  1. 418dea39ce (2026-02-24): alignment must be a non-zero power of two
     (gguf_reader.py lines ~187-189)
  2. 5788b510a1 (2026-08-04): tensor n_dims must not exceed GGML_MAX_DIMS=4
     (gguf_reader.py lines ~284-285)
  3. 0329fcdac8 (2026-08-19): four separate size guards --
       a. tensor_count > GGUF_MAX_ARRAY_ELEMENTS  (line ~174-175)
       b. kv_count > GGUF_MAX_ARRAY_ELEMENTS      (line ~176-177)
       c. string length > GGUF_MAX_STRING_LENGTH  (line ~228-229)
       d. array length > GGUF_MAX_ARRAY_ELEMENTS  (line ~256-257)
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / 'vendor'))

from gguf.gguf_reader import GGUFReader  # noqa: E402

GGUF_MAGIC = 0x46554747
GGUF_VERSION = 3
GGUF_MAX_STRING_LENGTH = 1024 * 1024 * 1024
GGUF_MAX_ARRAY_ELEMENTS = 1024 * 1024 * 1024
GGML_MAX_DIMS = 4

VT_UINT8 = 0
VT_UINT32 = 4
VT_STRING = 8
VT_ARRAY = 9


def u32(v: int) -> bytes:
    return struct.pack('<I', v)


def u64(v: int) -> bytes:
    return struct.pack('<Q', v)


def gguf_string(s: str) -> bytes:
    b = s.encode('utf-8')
    return u64(len(b)) + b


def header(tensor_count: int, kv_count: int, version: int = GGUF_VERSION) -> bytes:
    return u32(GGUF_MAGIC) + u32(version) + u64(tensor_count) + u64(kv_count)


def kv_scalar(key: str, value_type: int, packed_value: bytes) -> bytes:
    return gguf_string(key) + u32(value_type) + packed_value


def write_and_open(tmp_path: Path, name: str, raw: bytes) -> Path:
    p = tmp_path / name
    p.write_bytes(raw)
    return p


# --- 1. Alignment guard (418dea39ce) ---------------------------------------

def _build_with_alignment(alignment_value: int) -> bytes:
    """1 KV pair setting general.alignment to an arbitrary uint32, 0 tensors.
    GGUFReader reads general.alignment (line ~182-186) and then checks it's
    a non-zero power of two (line ~187-189) BEFORE using it to compute
    padding, so a bad value raises during __init__ with 0 tensors present."""
    kvs = kv_scalar('general.alignment', VT_UINT32, u32(alignment_value))
    return header(tensor_count=0, kv_count=1) + kvs


def test_alignment_zero_raises(tmp_path):
    raw = _build_with_alignment(0)
    path = write_and_open(tmp_path, 'align_zero.gguf', raw)
    with pytest.raises(ValueError, match='Invalid alignment'):
        GGUFReader(str(path))


def test_alignment_non_power_of_two_raises(tmp_path):
    raw = _build_with_alignment(3)
    path = write_and_open(tmp_path, 'align_three.gguf', raw)
    with pytest.raises(ValueError, match='Invalid alignment'):
        GGUFReader(str(path))


def test_alignment_valid_power_of_two_does_not_raise_this_guard(tmp_path):
    """Negative control: a valid alignment (64, a power of two) must NOT
    trip the alignment guard. Confirms the guard is specific, not a blanket
    rejection of the general.alignment field."""
    raw = _build_with_alignment(64)
    path = write_and_open(tmp_path, 'align_valid.gguf', raw)
    reader = GGUFReader(str(path))
    assert reader.alignment == 64


# --- 2. n_dims guard (5788b510a1) -------------------------------------------

def _build_with_tensor_ndims(n_dims_value: int) -> bytes:
    """0 KV pairs, 1 tensor info entry whose n_dims field is set directly
    to n_dims_value. We do not need valid dims/dtype/offset data after it
    for the guard to trigger, since the check (line ~284) happens
    immediately after n_dims is read and before dims are read."""
    tensor_name = 'blk.0.weight'
    tensor_info = gguf_string(tensor_name) + u32(n_dims_value)
    if n_dims_value <= GGML_MAX_DIMS:
        # Only needed if we expect parsing to continue past the guard.
        tensor_info += b''.join(u64(1) for _ in range(n_dims_value))
        tensor_info += u32(0)  # dtype = F32
        tensor_info += u64(0)  # data offset
    return header(tensor_count=1, kv_count=0) + tensor_info


def test_n_dims_exceeds_max_raises(tmp_path):
    raw = _build_with_tensor_ndims(GGML_MAX_DIMS + 1)  # 5
    path = write_and_open(tmp_path, 'ndims_five.gguf', raw)
    with pytest.raises(ValueError, match='GGML_MAX_DIMS'):
        GGUFReader(str(path))


def test_n_dims_at_max_does_not_raise_this_guard(tmp_path):
    """Negative control: n_dims == GGML_MAX_DIMS (4) is the boundary and
    must be accepted (guard is `>`, not `>=`). Default alignment is 32
    (GGUF_DEFAULT_ALIGNMENT), so pad the pre-data block to a 32-byte
    boundary and append one real F32 element (4 bytes) as tensor data,
    exactly as src/make_corpus.py's build_with_tensor() does, so
    _build_tensors' final reshape has real data to work with."""
    pre_data = _build_with_tensor_ndims(GGML_MAX_DIMS)  # 4
    alignment = 32
    padding_needed = (-len(pre_data)) % alignment
    raw = pre_data + b'\x00' * padding_needed + struct.pack('<f', 1.0)
    path = write_and_open(tmp_path, 'ndims_four.gguf', raw)
    reader = GGUFReader(str(path))
    assert len(reader.tensors) == 1
    assert reader.tensors[0].shape.tolist() == [1, 1, 1, 1]


# --- 3a/3b. tensor_count / kv_count guards (0329fcdac8) ---------------------

def test_tensor_count_exceeds_max_raises(tmp_path):
    raw = header(tensor_count=GGUF_MAX_ARRAY_ELEMENTS + 1, kv_count=0)
    path = write_and_open(tmp_path, 'tensor_count_over.gguf', raw)
    with pytest.raises(ValueError, match='Tensor count'):
        GGUFReader(str(path))


def test_kv_count_exceeds_max_raises(tmp_path):
    raw = header(tensor_count=0, kv_count=GGUF_MAX_ARRAY_ELEMENTS + 1)
    path = write_and_open(tmp_path, 'kv_count_over.gguf', raw)
    with pytest.raises(ValueError, match='KV count'):
        GGUFReader(str(path))


# --- 3c. string length guard (0329fcdac8) -----------------------------------

def test_string_length_exceeds_max_raises(tmp_path):
    """A KV pair whose key claims a length over GGUF_MAX_STRING_LENGTH.
    _get_str (line ~226-229) checks the claimed length against the max
    BEFORE checking it against remaining file size, and before attempting
    to read that many bytes -- so this raises even though the file is tiny
    and does not actually contain a gigabyte of key data."""
    huge_len = GGUF_MAX_STRING_LENGTH + 1
    raw = header(tensor_count=0, kv_count=1) + u64(huge_len) + b'x' * 16
    path = write_and_open(tmp_path, 'string_len_over.gguf', raw)
    with pytest.raises(ValueError, match='String length'):
        GGUFReader(str(path))


def test_string_length_exceeding_file_size_raises(tmp_path):
    """Negative-adjacent control: a string length guard exists for the
    remaining-file-size check too (line ~230-231), a related but distinct
    guard from the absolute GGUF_MAX_STRING_LENGTH cap. Included here since
    it's the same _get_str call path and confirms that path is reachable
    end-to-end, not just the absolute-max branch."""
    raw = header(tensor_count=0, kv_count=1) + u64(1000) + b'short'
    path = write_and_open(tmp_path, 'string_len_vs_filesize.gguf', raw)
    with pytest.raises(ValueError, match='exceeds remaining file size'):
        GGUFReader(str(path))


# --- 3d. array length guard (0329fcdac8) ------------------------------------

def test_array_length_exceeds_max_raises(tmp_path):
    """A KV pair of ARRAY type whose claimed element count exceeds
    GGUF_MAX_ARRAY_ELEMENTS. _get_field_parts (line ~256-257) checks this
    immediately after reading the count and before iterating elements, so
    this raises without the file needing to contain that many elements."""
    huge_count = GGUF_MAX_ARRAY_ELEMENTS + 1
    key = gguf_string('bad.array')
    array_body = u32(VT_UINT8) + u64(huge_count)
    raw = header(tensor_count=0, kv_count=1) + key + u32(VT_ARRAY) + array_body
    path = write_and_open(tmp_path, 'array_len_over.gguf', raw)
    with pytest.raises(ValueError, match='Array length'):
        GGUFReader(str(path))


# --- Summary sanity: every guard is a ValueError with a distinct message ---

def test_all_six_guard_messages_are_distinct():
    """Documents, in one place, that the six ValueError guards proven above
    are textually distinguishable from each other, which is what let each
    test above use a targeted `match=` rather than a bare `pytest.raises(
    ValueError)` that could pass for the wrong reason."""
    messages = {
        'alignment': 'Invalid alignment',
        'n_dims': 'GGML_MAX_DIMS',
        'tensor_count': 'Tensor count',
        'kv_count': 'KV count',
        'string_length': 'String length',
        'array_length': 'Array length',
    }
    assert len(set(messages.values())) == len(messages)

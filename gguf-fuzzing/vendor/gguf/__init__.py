# Minimal package init for the vendored, fuzzing-only subset of gguf-py.
#
# The upstream gguf/__init__.py does `from .gguf_reader import *` etc. across
# every module in the package (gguf_writer, metadata, vocab, tensor_mapping,
# scripts, ...). We only vendored the files needed to reach GGUFReader
# (gguf_reader.py, constants.py, quants.py, lazy.py), so we deliberately do
# NOT replicate that wildcard init here. Import GGUFReader directly:
#
#   from gguf.gguf_reader import GGUFReader
#
# See vendor/COMMIT.txt for the exact commit this subset was pulled from.

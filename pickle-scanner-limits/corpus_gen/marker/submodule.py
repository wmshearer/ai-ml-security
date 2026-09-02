"""A genuine submodule of corpus_gen.marker, used only to reproduce the
*shape* of CVE-2025-10157 (picklescan's unsafe-globals check used exact
module-name matching, so a GLOBAL opcode naming a submodule of a denylisted
module -- e.g. asyncio.unix_events instead of asyncio -- was not matched and
scored merely "suspicious" instead of "dangerous").

write_marker_via_submodule does exactly what corpus_gen.marker.write_marker
does: appends a timestamped line to evidence/markers/marker_log.txt. It
exists as a separate submodule purely so the pickled GLOBAL opcode names
corpus_gen.marker.submodule.write_marker_via_submodule, matching the
submodule-import evasion shape at the opcode level, without involving any
genuinely dangerous module.
"""
from __future__ import annotations

from corpus_gen.marker import write_marker


def write_marker_via_submodule(name: str) -> str:
    return write_marker(name)

"""
Join layer: reads a garak `.report.jsonl` file plus the shim's
`evidence/harness.db` and produces (garak_attempt, shim_record | None) pairs
so the normalizer/scorer can see the full tool_calls_made/retrieved_doc_ids
signal garak itself never captures (see shim.py's module docstring and
normalize.py's normalize_garak_attempt evidence comment).

Why joining is even necessary (verified against real data in this repo,
2026-08-17): garak's Attempt.as_dict() only ever writes
{text, lang, data_path, data_type, data_checksum, notes} per prompt/output —
there is no request_id, no HTTP header capture, nothing that ties an attempt
back to the shim's `X-Harness-Request-Id` response header. garak's own
RestGenerator has no hook to persist or echo back a response header into the
report. So the header the shim exposes (shim.py's chat()) is, in practice,
unusable as a join key from garak's report alone — confirmed by reading both
the shim's response-construction code and every key present in
evidence/garak_reports/acme_helpdesk_run1.report.jsonl.

Join key actually used: exact match on prompt text vs shim `message`
column, in file order, consumed once per shim row (positional/stateful
matching — see _match_by_prompt_text below). This is not a hash join on
text; duplicate prompt strings are resolved by first-available-unconsumed
shim row in `created_at` order, which is the correct disambiguator *only if*
the shim and the garak report were populated in the same relative order for
those duplicates (see quantified caveat below).

Quantified failure modes against the real data on disk
(evidence/garak_reports/acme_helpdesk_run1.report.jsonl,
evidence/harness.db, 108 rows):
  - 106 of 106 run1 attempts have an exact prompt-text match against shim
    rows 2..107 (shim row 1 is a manual "How do I reset my password?" smoke
    test never sent through garak; shim rows 108's last entries belong to
    run2). Positional order (garak `seq` ascending vs shim `created_at`
    ascending) agrees for all 106 -- confirmed by direct comparison, not
    assumed.
  - 19 of 106 run1 prompts are non-unique text (covering 40 of 106 attempts,
    ~38%) -- garak's own promptinject probe family reuses the same
    "base_text" carrier string (e.g. grammar-correction, summarization
    templates) across multiple attack_rogue_string variants, and reuses some
    combinations verbatim. Exact-text hash matching alone would misassign
    these; this join resolves them correctly ONLY because (a) the shim was
    populated by relaying the exact same garak run, so shim insertion order
    equals garak `seq` order 1:1, and (b) positional consumption (next
    unconsumed shim row with matching text) reconstructs that order. If the
    shim DB instead contained responses from multiple interleaved garak runs
    against the same probe set, or requests were retried out of order,
    positional matching would silently misattribute duplicate-text rows to
    the wrong attempt -- this is a real, documented weakness of text-based
    joining, not a hypothetical one.
  - 0 misses, 0 unresolved duplicates against the real run1 data once
    positional consumption is applied within duplicate-text groups (see
    tests/test_join.py for the reproduction).
  - garak run2 (acme_helpdesk_run2_antidan) writes the SAME (uuid, seq)
    attempt twice in its .report.jsonl -- once at status=1 (started, output
    already attached) and once at status=2 (complete, detector_results
    populated). This is garak's own reporting behavior, not a join
    artifact -- confirmed by diffing both records byte-for-byte. This join
    only keeps the status==2 (complete) copy per (uuid, seq) so a caller
    does not double-count one real attempt as two findings; normalize.py's
    own status handling additionally treats non-complete attempts as
    outcome="error" if a caller passes the status=1 copy through anyway.
"""
from __future__ import annotations

import json
import sqlite3
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterator, NamedTuple

DB_PATH = Path(__file__).resolve().parent.parent.parent / "evidence" / "harness.db"

_GARAK_STATUS_COMPLETE = 2


class JoinResult(NamedTuple):
    """One garak attempt paired with its shim record, if any was found."""

    attempt: dict[str, Any]
    shim_record: dict[str, Any] | None
    join_method: str  # "prompt_text_positional" | "unmatched"


def load_garak_attempts(report_path: str | Path) -> list[dict[str, Any]]:
    """Read a garak `.report.jsonl` and return only entry_type=="attempt"
    records, deduplicated by (uuid, seq) keeping the most-complete copy.

    garak writes one "attempt" line per status transition it observes for
    the same logical attempt (confirmed: acme_helpdesk_run2_antidan writes
    (uuid, seq)=(6327deb4-..., 0) twice, status 1 then 2). Keeping the
    highest status value per (uuid, seq) is the correct dedup rule because
    garak's own Attempt.status is a monotonically increasing enum
    (0=not attempted, 1=started, 2=complete; see normalize.py's
    _GARAK_STATUS_COMPLETE comment) -- a later-status line strictly
    supersedes an earlier one for the same attempt, never contradicts it
    (verified: the two acme_helpdesk_run2_antidan lines are identical apart
    from status and detector_results, which is populated only once the
    attempt actually completes).
    """
    best: dict[tuple[str, int], dict[str, Any]] = {}
    with open(report_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            if record.get("entry_type") != "attempt":
                continue
            key = (record.get("uuid"), record.get("seq"))
            existing = best.get(key)
            if existing is None or (record.get("status") or 0) > (existing.get("status") or 0):
                best[key] = record
    # Preserve seq order for deterministic, reproducible output.
    return sorted(best.values(), key=lambda a: (a.get("seq") if a.get("seq") is not None else 0))


def _attempt_prompt_text(attempt: dict[str, Any]) -> str | None:
    """Extract the first user-turn prompt text from a garak attempt record.

    garak's Attempt.as_dict() nests prompt text at prompt.turns[0].content.text
    (confirmed against evidence/garak_reports/*.report.jsonl -- this is NOT
    the flat `attempt["prompt"]` string shape normalize.py's own docstring
    describes/test fixtures use; see join.py module docstring / handback
    notes for that discrepancy).
    """
    prompt = attempt.get("prompt")
    if isinstance(prompt, str):
        return prompt
    if isinstance(prompt, dict):
        turns = prompt.get("turns") or []
        if turns:
            content = turns[0].get("content") or {}
            return content.get("text")
    return None


def load_shim_records(db_path: str | Path = DB_PATH) -> list[dict[str, Any]]:
    """Read every recorded_responses row, oldest first (created_at, then
    rowid as a stable tiebreaker for same-second timestamps -- SQLite's
    datetime('now') default has only second resolution, and several rows in
    the real DB share a created_at second).
    """
    conn = sqlite3.connect(db_path)
    try:
        rows = conn.execute(
            "SELECT request_id, message, reply, retrieved_doc_ids, tool_calls_made, created_at "
            "FROM recorded_responses ORDER BY created_at, rowid"
        ).fetchall()
    finally:
        conn.close()
    records = []
    for request_id, message, reply, doc_ids_json, tool_calls_json, created_at in rows:
        records.append(
            {
                "request_id": request_id,
                "message": message,
                "reply": reply,
                "retrieved_doc_ids": json.loads(doc_ids_json),
                "tool_calls_made": json.loads(tool_calls_json),
                "created_at": created_at,
            }
        )
    return records


def join_attempts_to_shim(
    attempts: list[dict[str, Any]],
    shim_records: list[dict[str, Any]],
) -> list[JoinResult]:
    """Positional-within-duplicate-group join: for each attempt (in file
    order), consume the earliest not-yet-consumed shim record whose
    `message` exactly equals the attempt's prompt text.

    This is a queue-per-distinct-message strategy, not a plain dict lookup,
    specifically so that N attempts sharing the same prompt text correctly
    consume N distinct shim rows in the same relative order, rather than all
    resolving to the first (or a random) matching row. See module docstring
    for the quantified duplicate-rate this defends against (19/106 distinct
    prompts, 40/106 attempts in the real run1 data) and the ordering
    assumption it depends on.
    """
    queues: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in shim_records:
        queues[record["message"]].append(record)

    results: list[JoinResult] = []
    for attempt in attempts:
        prompt_text = _attempt_prompt_text(attempt)
        queue = queues.get(prompt_text) if prompt_text is not None else None
        if queue:
            shim_record = queue.pop(0)
            results.append(JoinResult(attempt, shim_record, "prompt_text_positional"))
        else:
            results.append(JoinResult(attempt, None, "unmatched"))
    return results


def join_report_file(
    report_path: str | Path,
    db_path: str | Path = DB_PATH,
) -> list[JoinResult]:
    """Convenience end-to-end entry point: load one garak report file, load
    the shim DB, join. Kept separate from load_garak_attempts/
    load_shim_records/join_attempts_to_shim so callers (and tests) can
    supply fixture data to any stage without touching the filesystem.
    """
    attempts = load_garak_attempts(report_path)
    shim_records = load_shim_records(db_path)
    return join_attempts_to_shim(attempts, shim_records)


def unmatched_shim_records(
    shim_records: list[dict[str, Any]],
    join_results: list[JoinResult],
) -> list[dict[str, Any]]:
    """Shim rows never consumed by any attempt in join_results -- e.g. the
    manual smoke-test call ("How do I reset my password?") that was never
    routed through garak, or a second garak run's rows joined separately.
    Exposed so a caller assembling a report can decide whether to surface
    these (harness-native evidence with no attack-tool provenance) rather
    than silently dropping them.
    """
    consumed_ids = {r.shim_record["request_id"] for r in join_results if r.shim_record is not None}
    return [r for r in shim_records if r["request_id"] not in consumed_ids]

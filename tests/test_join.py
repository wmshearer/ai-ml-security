"""
Unit tests for src/harness/join.py.

Runs entirely against synthetic fixture files (a temp .report.jsonl + a temp
sqlite DB built with the exact schema shim.py creates) -- no dependency on
the real evidence/ files, garak, PyRIT, or Ollama, so this suite stays green
even if the real evidence/ data changes shape.
"""
from __future__ import annotations

import json
import sqlite3
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src.harness import join  # noqa: E402


def _write_report_jsonl(path: Path, attempts: list[dict]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for a in attempts:
            record = {"entry_type": "attempt", **a}
            f.write(json.dumps(record) + "\n")


def _write_shim_db(path: Path, rows: list[tuple[str, str, str, list, list, str]]) -> None:
    conn = sqlite3.connect(path)
    conn.execute(
        """
        CREATE TABLE recorded_responses (
            request_id TEXT PRIMARY KEY,
            message TEXT NOT NULL,
            reply TEXT NOT NULL,
            retrieved_doc_ids TEXT NOT NULL,
            tool_calls_made TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )
    for request_id, message, reply, doc_ids, tool_calls, created_at in rows:
        conn.execute(
            "INSERT INTO recorded_responses VALUES (?, ?, ?, ?, ?, ?)",
            (request_id, message, reply, json.dumps(doc_ids), json.dumps(tool_calls), created_at),
        )
    conn.commit()
    conn.close()


def _attempt(uuid: str, seq: int, status: int, prompt_text: str, detector_results: dict | None = None) -> dict:
    return {
        "uuid": uuid,
        "seq": seq,
        "status": status,
        "probe_classname": "promptinject.HijackKillHumans",
        "prompt": {"turns": [{"role": "user", "content": {"text": prompt_text}}]},
        "outputs": [{"text": "some output"}],
        "detector_results": detector_results or {},
        "goal": "test",
    }


# --- load_garak_attempts: dedup by (uuid, seq), keep highest status -------


def test_load_garak_attempts_dedups_status1_then_status2():
    with tempfile.TemporaryDirectory() as tmp:
        report_path = Path(tmp) / "run.report.jsonl"
        _write_report_jsonl(
            report_path,
            [
                _attempt("aaa", 0, 1, "prompt A"),  # started, no detector_results yet
                _attempt("aaa", 0, 2, "prompt A", {"det.X": [1.0]}),  # complete
            ],
        )
        attempts = join.load_garak_attempts(report_path)
        assert len(attempts) == 1
        assert attempts[0]["status"] == 2
        assert attempts[0]["detector_results"] == {"det.X": [1.0]}


def test_load_garak_attempts_preserves_seq_order():
    with tempfile.TemporaryDirectory() as tmp:
        report_path = Path(tmp) / "run.report.jsonl"
        _write_report_jsonl(
            report_path,
            [
                _attempt("ccc", 2, 1, "prompt C"),
                _attempt("aaa", 0, 1, "prompt A"),
                _attempt("bbb", 1, 1, "prompt B"),
            ],
        )
        attempts = join.load_garak_attempts(report_path)
        assert [a["seq"] for a in attempts] == [0, 1, 2]


def test_load_garak_attempts_skips_non_attempt_lines():
    with tempfile.TemporaryDirectory() as tmp:
        report_path = Path(tmp) / "run.report.jsonl"
        with open(report_path, "w") as f:
            f.write(json.dumps({"entry_type": "init"}) + "\n")
            f.write(json.dumps({"entry_type": "attempt", "uuid": "x", "seq": 0, "status": 1,
                                 "prompt": {"turns": [{"content": {"text": "hi"}}]}}) + "\n")
            f.write(json.dumps({"entry_type": "digest"}) + "\n")
        attempts = join.load_garak_attempts(report_path)
        assert len(attempts) == 1


# --- join_attempts_to_shim: exact match + positional duplicate handling ---


def test_join_matches_unique_prompt_text():
    attempts = [_attempt("a1", 0, 2, "unique prompt")]
    shim_records = join.load_shim_records  # not used here; build directly
    records = [
        {"request_id": "r1", "message": "unique prompt", "reply": "ok",
         "retrieved_doc_ids": [], "tool_calls_made": [], "created_at": "2026-01-01 00:00:00"}
    ]
    results = join.join_attempts_to_shim(attempts, records)
    assert len(results) == 1
    assert results[0].shim_record is not None
    assert results[0].shim_record["request_id"] == "r1"
    assert results[0].join_method == "prompt_text_positional"


def test_join_no_match_returns_none_shim_record():
    attempts = [_attempt("a1", 0, 2, "prompt with no shim row")]
    results = join.join_attempts_to_shim(attempts, [])
    assert results[0].shim_record is None
    assert results[0].join_method == "unmatched"


def test_join_duplicate_prompt_text_resolves_positionally_not_by_hash():
    # Two attempts share identical prompt text; two shim rows share the same
    # text too, in the same relative order (created_at ascending). This is
    # exactly the pattern found in the real run1 data (19 duplicate prompts
    # covering 40/106 attempts) -- a plain dict/hash join would either lose
    # one match or double-assign the same shim row to both attempts.
    attempts = [
        _attempt("a1", 0, 2, "dup prompt"),
        _attempt("a2", 1, 2, "dup prompt"),
    ]
    records = [
        {"request_id": "r-first", "message": "dup prompt", "reply": "first reply",
         "retrieved_doc_ids": [], "tool_calls_made": [], "created_at": "2026-01-01 00:00:00"},
        {"request_id": "r-second", "message": "dup prompt", "reply": "second reply",
         "retrieved_doc_ids": [], "tool_calls_made": [{"name": "send_email"}], "created_at": "2026-01-01 00:00:01"},
    ]
    results = join.join_attempts_to_shim(attempts, records)
    assert results[0].shim_record["request_id"] == "r-first"
    assert results[1].shim_record["request_id"] == "r-second"
    # Confirms the second attempt is NOT silently matched to the exhausted first row
    # and does NOT lose its distinct tool_calls_made evidence.
    assert results[1].shim_record["tool_calls_made"] == [{"name": "send_email"}]


def test_join_more_attempts_than_shim_rows_leaves_extras_unmatched():
    attempts = [
        _attempt("a1", 0, 2, "dup prompt"),
        _attempt("a2", 1, 2, "dup prompt"),
        _attempt("a3", 2, 2, "dup prompt"),
    ]
    records = [
        {"request_id": "r1", "message": "dup prompt", "reply": "x",
         "retrieved_doc_ids": [], "tool_calls_made": [], "created_at": "2026-01-01 00:00:00"},
    ]
    results = join.join_attempts_to_shim(attempts, records)
    matched = [r for r in results if r.shim_record is not None]
    unmatched = [r for r in results if r.shim_record is None]
    assert len(matched) == 1
    assert len(unmatched) == 2


# --- unmatched_shim_records -------------------------------------------------


def test_unmatched_shim_records_excludes_consumed_rows():
    shim_records = [
        {"request_id": "r1", "message": "matched", "reply": "x", "retrieved_doc_ids": [], "tool_calls_made": []},
        {"request_id": "r2", "message": "orphan", "reply": "y", "retrieved_doc_ids": [], "tool_calls_made": []},
    ]
    attempts = [_attempt("a1", 0, 2, "matched")]
    results = join.join_attempts_to_shim(attempts, shim_records)
    unused = join.unmatched_shim_records(shim_records, results)
    assert len(unused) == 1
    assert unused[0]["request_id"] == "r2"


# --- load_shim_records: sanity check against a real sqlite file -----------


def test_load_shim_records_reads_db_in_created_at_order():
    with tempfile.TemporaryDirectory() as tmp:
        db_path = Path(tmp) / "harness.db"
        _write_shim_db(
            db_path,
            [
                ("r2", "second", "reply2", [], [], "2026-01-01 00:00:02"),
                ("r1", "first", "reply1", [], [{"name": "read_file", "args": {"path": "/etc/hosts"}}], "2026-01-01 00:00:01"),
            ],
        )
        records = join.load_shim_records(db_path)
        assert [r["request_id"] for r in records] == ["r1", "r2"]
        assert records[0]["tool_calls_made"] == [{"name": "read_file", "args": {"path": "/etc/hosts"}}]


# --- join_report_file: end-to-end against temp fixture files --------------


def test_join_report_file_end_to_end():
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        report_path = tmp_path / "run.report.jsonl"
        db_path = tmp_path / "harness.db"

        _write_report_jsonl(report_path, [_attempt("a1", 0, 2, "hello")])
        _write_shim_db(
            db_path,
            [("r1", "hello", "hi there", [], [{"name": "send_email", "args": {"to": "x@example.com"}}], "2026-01-01 00:00:00")],
        )

        results = join.join_report_file(report_path, db_path)
        assert len(results) == 1
        assert results[0].shim_record["tool_calls_made"][0]["name"] == "send_email"

"""
Recording shim: a thin FastAPI proxy in front of the real target's /chat.

Why this exists (research item "Recommended integration design"): garak's
RestGenerator only extracts one configured response_json_field ("reply") and
PyRIT's HTTPXAPITarget callback_function likewise only has to return the
string a Scorer judges. Neither tool's stock config surface can see
tool_calls_made (needed for LLM03 excessive-agency detection) or
retrieved_doc_ids (needed for the LLM09 RAG-poisoning check) at the same
time as the reply text. Rather than solve that twice (a garak generator
subclass AND a custom PyRIT parse path), this shim sits in front of /chat
once, persists the FULL response for every request, and returns the
response body UNCHANGED so garak/PyRIT see a completely normal single-field
endpoint. The harness's own normalizer/scorer code joins a garak or PyRIT
result back to the full recorded response by request_id after the run.

This is additive: src/target/main.py is not modified. Point garak/PyRIT at
this shim's /chat instead of the real target's /chat; the shim forwards
1:1 and changes nothing about the request/response contract.

Storage: SQLite (evidence/harness.db), not JSONL, for three reasons:
1. Concurrency safety. garak's RestGenerator is parallel_capable by default
   (research item 4) — even capped to sequential in config, a stray
   concurrent run or a future PyRIT max_requests_per_minute > 1 means
   multiple writers; SQLite's file locking handles concurrent writes
   correctly, a shared-append JSONL file does not (interleaved partial
   writes are a real risk under concurrent access).
2. Consistency with the rest of the stack. PyRIT's own local memory backend
   is SQLite via SQLAlchemy (research item 2, correcting Phase 0's DuckDB
   assumption) — reusing SQLite here means the harness doesn't introduce a
   second, different persistence technology for what is structurally the
   same job (record one row per attempt, look it up later by id).
3. Queryability. The normalizer needs "give me the full response for
   request_id X" — trivial as an indexed SQL lookup, requires a full-file
   scan (or a second index file) with JSONL.

Run with:
    uvicorn src.harness.shim:app --port 8001

Then point garak/PyRIT at http://127.0.0.1:8001/chat instead of :8000/chat.
Requires the real target (uvicorn src.target.main:app, port 8000) already
running — the shim forwards to it, it does not reimplement it.
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
from fastapi import FastAPI, Response
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("harness-shim")

REAL_TARGET_URL = "http://127.0.0.1:8000/chat"

# Read from the environment rather than importing src.target.config: the shim is
# deliberately independent of the target package so it can front any HTTP target,
# not just this one. Default must exceed the target's OLLAMA_TIMEOUT (240s).
SHIM_TIMEOUT = float(os.environ.get("HARNESS_SHIM_TIMEOUT", "270"))
DB_PATH = Path(__file__).resolve().parent.parent.parent / "evidence" / "harness.db"

# Matches src/target/main.py's ChatRequest/ChatResponse contract exactly
# (fields verified directly from main.py:33-40) so the shim is a transparent
# pass-through, not a reinterpretation of the target's API.


class ChatRequest(BaseModel):
    message: str


class ChatResponse(BaseModel):
    reply: str
    retrieved_doc_ids: list[str]
    tool_calls_made: list[dict]


def _init_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS recorded_responses (
                request_id TEXT PRIMARY KEY,
                message TEXT NOT NULL,
                reply TEXT NOT NULL,
                retrieved_doc_ids TEXT NOT NULL,   -- JSON-encoded list[str]
                tool_calls_made TEXT NOT NULL,     -- JSON-encoded list[dict]
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
            """
        )
        conn.commit()
    finally:
        conn.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    _init_db()
    yield


app = FastAPI(title="Recording shim for garak/PyRIT (Phase 2)", lifespan=lifespan)


def _record(request_id: str, message: str, chat_response: ChatResponse) -> None:
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute(
            "INSERT INTO recorded_responses "
            "(request_id, message, reply, retrieved_doc_ids, tool_calls_made) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                request_id,
                message,
                chat_response.reply,
                json.dumps(chat_response.retrieved_doc_ids),
                json.dumps(chat_response.tool_calls_made),
            ),
        )
        conn.commit()
    finally:
        conn.close()


@app.post("/chat", response_model=ChatResponse)
async def chat(req: ChatRequest, response: Response) -> ChatResponse:
    request_id = str(uuid.uuid4())

    # Must be MORE generous than the target's own Ollama budget, not equal to it.
    # Both were previously hardcoded at 120s, so a slow upstream call tripped the
    # target and the shim simultaneously and the shim's own error masked the
    # target's real behaviour. SHIM_TIMEOUT (270s) > OLLAMA_TIMEOUT (240s), and
    # garak's outer request_timeout (300s) is more generous still.
    async with httpx.AsyncClient(timeout=SHIM_TIMEOUT) as client:
        resp = await client.post(REAL_TARGET_URL, json={"message": req.message})
        resp.raise_for_status()
        chat_response = ChatResponse(**resp.json())

    _record(request_id, req.message, chat_response)
    logger.info("recorded request_id=%s tool_calls=%d retrieved_docs=%s",
                request_id, len(chat_response.tool_calls_made), chat_response.retrieved_doc_ids)

    # Exposed so a caller that wants to join back to the full record can
    # (garak/PyRIT themselves will ignore an unrecognized header); the
    # response body itself is returned byte-for-byte equivalent to what the
    # real target would have returned, per the "transparent pass-through"
    # contract this shim promises.
    response.headers["X-Harness-Request-Id"] = request_id
    return chat_response


@app.get("/healthz")
async def healthz() -> dict:
    return {"status": "ok"}


def get_recorded_response(request_id: str) -> dict | None:
    """Lookup helper for the harness's own normalizer/scorer code — not
    used by garak/PyRIT themselves, which only ever see the /chat endpoint.
    """
    conn = sqlite3.connect(DB_PATH)
    try:
        row = conn.execute(
            "SELECT message, reply, retrieved_doc_ids, tool_calls_made, created_at "
            "FROM recorded_responses WHERE request_id = ?",
            (request_id,),
        ).fetchone()
    finally:
        conn.close()
    if row is None:
        return None
    message, reply, doc_ids_json, tool_calls_json, created_at = row
    return {
        "request_id": request_id,
        "message": message,
        "reply": reply,
        "retrieved_doc_ids": json.loads(doc_ids_json),
        "tool_calls_made": json.loads(tool_calls_json),
        "created_at": created_at,
    }

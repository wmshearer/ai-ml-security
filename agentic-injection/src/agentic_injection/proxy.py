"""Recording proxy: a thin FastAPI pass-through in front of Ollama's own API.

Modeled on the pattern in
projects/ai-redteam-harness/src/harness/shim.py (thin FastAPI proxy, SQLite
recording, pass response through unchanged) but rewritten against a
different protocol, per the research brief's Q0 finding: aider talks
directly to Ollama's native API (`ollama_chat/<model>` -> litellm ->
`POST {OLLAMA_API_BASE}/api/chat`), not to any custom `{message} -> {reply,
tool_calls_made}` contract. There is no bespoke target app in front of
Ollama here, so this proxy sits directly in front of Ollama itself.

What it records and why:
- Every request/response pair to /api/chat is stored verbatim (raw JSON in,
  raw JSON out), keyed by a request_id and a run_id (the run_id is supplied
  by the caller via the `X-Run-Id` header set by 04_run_case.py, so every
  LLM-layer turn can be joined back to the side-effect record captured
  separately from the scratch repo's git history and filesystem state).
- The response's `message.tool_calls` field (if present) is pulled out into
  its own column for convenience, but this is explicitly NOT the
  "tool_fired" signal for this project -- see score.py and README.md. Aider
  does not drive its edits through this field in its default SEARCH/REPLACE
  edit loop; it parses the reply text. tool_calls here is recorded because
  it is an interesting secondary signal (did the *model* attempt a
  structured tool call at all), not because it is authoritative for
  whether the *agent* acted.
- Every other path (e.g. /api/tags, /api/show, used by litellm to look up
  model capabilities) is forwarded 1:1 with no recording, so aider sees a
  completely normal Ollama server end to end.

Run with:
    .venv/bin/uvicorn agentic_injection.proxy:app --port 11435

Then point aider at it via OLLAMA_API_BASE=http://127.0.0.1:11435.
Requires a real Ollama server already running at OLLAMA_UPSTREAM_URL
(default http://127.0.0.1:11434) -- this proxy forwards to it, it does not
reimplement it.
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
from fastapi import FastAPI, Request, Response

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("agentic-injection-proxy")

OLLAMA_UPSTREAM_URL = os.environ.get("OLLAMA_UPSTREAM_URL", "http://127.0.0.1:11434")

# Must exceed how long a small local model can plausibly take on a big
# multi-turn coding session; Ollama itself has no built-in request timeout,
# so this is purely about not giving up on the upstream too early.
PROXY_TIMEOUT = float(os.environ.get("AGENTIC_INJECTION_PROXY_TIMEOUT", "300"))

DB_PATH = Path(
    os.environ.get(
        "AGENTIC_INJECTION_DB_PATH",
        str(Path(__file__).resolve().parent.parent.parent / "evidence" / "proxy.db"),
    )
)


def _init_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS recorded_calls (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                request_id TEXT NOT NULL,
                run_id TEXT,
                path TEXT NOT NULL,
                request_body TEXT NOT NULL,
                response_body TEXT NOT NULL,
                status_code INTEGER NOT NULL,
                tool_calls_requested TEXT,   -- JSON-encoded list[dict] or NULL
                reply_content TEXT,          -- message.content convenience column
                duration_seconds REAL NOT NULL,
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


app = FastAPI(title="Ollama recording proxy (agentic-injection)", lifespan=lifespan)


def _extract_chat_fields(response_json: dict) -> tuple[str | None, list | None]:
    """Pull message.content and message.tool_calls out of an Ollama /api/chat
    response body, tolerating a missing/malformed shape rather than raising,
    since this is a recording convenience column, not the source of truth
    (the full response_body column always has the raw bytes regardless).
    """
    try:
        message = response_json.get("message", {})
        content = message.get("content")
        tool_calls = message.get("tool_calls")
        return content, tool_calls
    except AttributeError:
        return None, None


def _record_chat_call(
    request_id: str,
    run_id: str | None,
    path: str,
    request_body: bytes,
    response_body: bytes,
    status_code: int,
    duration_seconds: float,
) -> None:
    reply_content = None
    tool_calls = None
    try:
        response_json = json.loads(response_body)
        reply_content, tool_calls = _extract_chat_fields(response_json)
    except json.JSONDecodeError:
        pass

    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute(
            "INSERT INTO recorded_calls "
            "(request_id, run_id, path, request_body, response_body, status_code, "
            " tool_calls_requested, reply_content, duration_seconds) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                request_id,
                run_id,
                path,
                request_body.decode("utf-8", errors="replace"),
                response_body.decode("utf-8", errors="replace"),
                status_code,
                json.dumps(tool_calls) if tool_calls is not None else None,
                reply_content,
                duration_seconds,
            ),
        )
        conn.commit()
    finally:
        conn.close()


@app.get("/healthz")
async def healthz() -> dict:
    return {"status": "ok", "upstream": OLLAMA_UPSTREAM_URL}


@app.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "DELETE", "HEAD"])
async def proxy(full_path: str, request: Request) -> Response:
    request_id = str(uuid.uuid4())
    run_id = request.headers.get("x-run-id")
    body = await request.body()
    upstream_url = f"{OLLAMA_UPSTREAM_URL}/{full_path}"

    # Strip hop-by-hop / host headers so httpx sets its own correctly against
    # the upstream host instead of forwarding this request's original Host.
    forward_headers = {
        k: v for k, v in request.headers.items() if k.lower() not in ("host", "content-length")
    }

    start = time.monotonic()
    async with httpx.AsyncClient(timeout=PROXY_TIMEOUT) as client:
        upstream_resp = await client.request(
            request.method,
            upstream_url,
            content=body,
            headers=forward_headers,
            params=request.query_params,
        )
    duration = time.monotonic() - start

    if full_path == "api/chat":
        _record_chat_call(
            request_id=request_id,
            run_id=run_id,
            path=full_path,
            request_body=body,
            response_body=upstream_resp.content,
            status_code=upstream_resp.status_code,
            duration_seconds=duration,
        )
        logger.info(
            "recorded api/chat request_id=%s run_id=%s status=%d duration=%.2fs",
            request_id, run_id, upstream_resp.status_code, duration,
        )

    response_headers = {
        k: v
        for k, v in upstream_resp.headers.items()
        if k.lower() not in ("content-length", "transfer-encoding", "content-encoding")
    }
    response_headers["X-Proxy-Request-Id"] = request_id
    return Response(
        content=upstream_resp.content,
        status_code=upstream_resp.status_code,
        headers=response_headers,
        media_type=upstream_resp.headers.get("content-type"),
    )


def get_recorded_calls(run_id: str | None = None) -> list[dict]:
    """Lookup helper for the scorer -- not used by aider/Ollama themselves."""
    conn = sqlite3.connect(DB_PATH)
    try:
        if run_id is not None:
            rows = conn.execute(
                "SELECT request_id, run_id, path, request_body, response_body, "
                "status_code, tool_calls_requested, reply_content, duration_seconds, created_at "
                "FROM recorded_calls WHERE run_id = ? ORDER BY created_at",
                (run_id,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT request_id, run_id, path, request_body, response_body, "
                "status_code, tool_calls_requested, reply_content, duration_seconds, created_at "
                "FROM recorded_calls ORDER BY created_at"
            ).fetchall()
    finally:
        conn.close()

    columns = [
        "request_id", "run_id", "path", "request_body", "response_body",
        "status_code", "tool_calls_requested", "reply_content", "duration_seconds", "created_at",
    ]
    return [dict(zip(columns, row)) for row in rows]

"""Tests for src/agentic_injection/proxy.py.

Uses FastAPI's TestClient against a mocked upstream (httpx respx-style hand
rolled fixture, since we don't want to depend on Ollama actually running
for the unit-level tests) plus a temp SQLite DB per test via monkeypatching
DB_PATH, so these tests never touch evidence/proxy.db.
"""
from __future__ import annotations

import json
import sqlite3

import pytest
from fastapi.testclient import TestClient

from agentic_injection import proxy as proxy_mod


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(proxy_mod, "DB_PATH", tmp_path / "test_proxy.db")
    with TestClient(proxy_mod.app) as c:
        yield c


def test_healthz(client):
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_db_initialized_on_startup(tmp_path, monkeypatch):
    db_path = tmp_path / "init_test.db"
    monkeypatch.setattr(proxy_mod, "DB_PATH", db_path)
    with TestClient(proxy_mod.app):
        pass
    assert db_path.exists()
    conn = sqlite3.connect(db_path)
    try:
        tables = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    finally:
        conn.close()
    assert ("recorded_calls",) in tables


def test_extract_chat_fields_normal_shape():
    body = {"message": {"role": "assistant", "content": "hi", "tool_calls": [{"function": {"name": "x"}}]}}
    content, tool_calls = proxy_mod._extract_chat_fields(body)
    assert content == "hi"
    assert tool_calls == [{"function": {"name": "x"}}]


def test_extract_chat_fields_missing_message_does_not_raise():
    content, tool_calls = proxy_mod._extract_chat_fields({})
    assert content is None
    assert tool_calls is None


def test_non_chat_path_is_not_recorded(client, tmp_path, monkeypatch):
    """/api/tags (or any path other than api/chat) must be forwarded without
    a row being written to recorded_calls -- only api/chat is the
    LLM-layer signal this project records.
    """
    calls = []

    class FakeResponse:
        status_code = 200
        content = b'{"models": []}'
        headers = {"content-type": "application/json"}

    class FakeAsyncClient:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def request(self, method, url, content, headers, params):
            calls.append(url)
            return FakeResponse()

    monkeypatch.setattr(proxy_mod.httpx, "AsyncClient", FakeAsyncClient)
    resp = client.get("/api/tags")
    assert resp.status_code == 200

    conn = sqlite3.connect(proxy_mod.DB_PATH)
    try:
        rows = conn.execute("SELECT * FROM recorded_calls").fetchall()
    finally:
        conn.close()
    assert rows == []


def test_chat_path_is_recorded_with_reply_and_tool_calls(client, monkeypatch):
    response_json = {
        "message": {
            "role": "assistant",
            "content": "hello there",
            "tool_calls": [{"function": {"name": "write_file", "arguments": "{}"}}],
        }
    }

    class FakeResponse:
        status_code = 200
        content = json.dumps(response_json).encode()
        headers = {"content-type": "application/json"}

    class FakeAsyncClient:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def request(self, method, url, content, headers, params):
            return FakeResponse()

    monkeypatch.setattr(proxy_mod.httpx, "AsyncClient", FakeAsyncClient)
    resp = client.post("/api/chat", json={"model": "qwen3:4b", "messages": []})
    assert resp.status_code == 200

    conn = sqlite3.connect(proxy_mod.DB_PATH)
    try:
        rows = conn.execute(
            "SELECT reply_content, tool_calls_requested, status_code FROM recorded_calls"
        ).fetchall()
    finally:
        conn.close()
    assert len(rows) == 1
    reply_content, tool_calls_requested, status_code = rows[0]
    assert reply_content == "hello there"
    assert json.loads(tool_calls_requested) == [{"function": {"name": "write_file", "arguments": "{}"}}]
    assert status_code == 200


def test_response_passed_through_unchanged(client, monkeypatch):
    """The core design contract: whatever bytes Ollama returns for
    /api/chat, the proxy's client receives byte-for-byte identical content.
    """
    raw_body = b'{"message": {"role": "assistant", "content": "exact bytes test"}, "done": true}'

    class FakeResponse:
        status_code = 200
        content = raw_body
        headers = {"content-type": "application/json"}

    class FakeAsyncClient:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def request(self, method, url, content, headers, params):
            return FakeResponse()

    monkeypatch.setattr(proxy_mod.httpx, "AsyncClient", FakeAsyncClient)
    resp = client.post("/api/chat", json={"model": "qwen3:4b", "messages": []})
    assert resp.content == raw_body

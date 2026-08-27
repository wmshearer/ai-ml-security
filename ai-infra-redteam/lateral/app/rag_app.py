"""
Minimal RAG application used as the stack's front door for this test.

This is the "foothold" container in the attack chain: in a real deployment
this is the piece of code most likely to have an exploitable dependency or
application bug (it is the one talking to the public internet / end users),
so it is the realistic place for an attacker to land first. Nothing in this
file is itself vulnerable on purpose - the point of this component is what
becomes reachable from a plain, unremarkable app container once an attacker
is running code inside it, not a bug in this app's own logic.

It does two boring, real things:
  - on startup, embeds a couple of tiny "documents" and writes them into
    ChromaDB under one tenant/database (its own)
  - exposes a /query endpoint that takes a question, does a naive similarity
    stub (no real embedding model - out of scope), and asks Ollama to answer
    using whatever it got back from Chroma

It also reads a fake internal API token from its environment and writes it
to a config file on disk, because that is exactly how a real internal
service is configured (env var or mounted config file, both checked by the
enumeration step later). The token is planted, fake, and clearly labeled as
such - see PLANTED_SECRET below and FINDINGS.md.
"""
import os
import time
import json
from pathlib import Path

import requests
from fastapi import FastAPI

CHROMA_URL = os.environ.get("CHROMA_URL", "http://chroma:8000")
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://ollama:11434")
TENANT = "default_tenant"
DATABASE = "default_database"
COLLECTION_NAME = "app_notes"

# Planted, fake credential - simulates a real internal token an app
# container would hold (e.g. for a downstream billing/auth service that is
# NOT part of this stack). This is realistic: apps routinely carry secrets
# for services beyond the ones being tested. It is obviously fake and is
# never a real credential of any kind.
PLANTED_SECRET = os.environ.get("INTERNAL_API_TOKEN", "INTERNAL_API_TOKEN_PLANTED_9f3a7c")

app = FastAPI()


def write_config_file():
    """Write the app's own config to disk, the way a real service does,
    so the enumeration step can demonstrate reading secrets from a config
    file as well as from the environment."""
    cfg = {
        "chroma_url": CHROMA_URL,
        "ollama_url": OLLAMA_URL,
        "internal_api_token": PLANTED_SECRET,
    }
    Path("/app/config.json").write_text(json.dumps(cfg, indent=2))


def wait_for(url: str, name: str, timeout_s: int = 90):
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            r = requests.get(url, timeout=2)
            if r.status_code < 500:
                return True
        except requests.RequestException:
            pass
        time.sleep(2)
    print(f"WARNING: {name} did not become ready within {timeout_s}s")
    return False


def ensure_collection() -> str:
    """Create (or fetch) this app's own Chroma collection and seed it with
    one small document. Returns the collection UUID."""
    base = f"{CHROMA_URL}/api/v2/tenants/{TENANT}/databases/{DATABASE}"
    requests.post(f"{CHROMA_URL}/api/v2/tenants", json={"name": TENANT}, timeout=5)
    requests.post(f"{CHROMA_URL}/api/v2/tenants/{TENANT}/databases",
                  json={"name": DATABASE}, timeout=5)
    r = requests.post(f"{base}/collections", json={"name": COLLECTION_NAME}, timeout=5)
    if r.status_code == 200:
        coll_id = r.json()["id"]
    else:
        r = requests.get(f"{base}/collections", timeout=5)
        coll_id = next(c["id"] for c in r.json() if c["name"] == COLLECTION_NAME)

    requests.post(
        f"{base}/collections/{coll_id}/add",
        json={
            "ids": ["note-1"],
            "documents": ["The RAG app's own note: nothing sensitive here."],
            "embeddings": [[0.1, 0.2, 0.3, 0.4]],
        },
        timeout=5,
    )
    return coll_id


@app.on_event("startup")
def startup():
    write_config_file()
    wait_for(f"{CHROMA_URL}/api/v2/heartbeat", "chroma")
    wait_for(f"{OLLAMA_URL}/api/tags", "ollama")
    try:
        app.state.collection_id = ensure_collection()
    except Exception as e:
        print(f"WARNING: could not seed chroma collection: {e}")
        app.state.collection_id = None


@app.get("/health")
def health():
    return {"status": "ok", "collection_id": getattr(app.state, "collection_id", None)}


@app.post("/query")
def query(payload: dict):
    """Naive RAG: fetch this app's own note from Chroma, stuff it in a
    prompt, ask Ollama. Good enough to prove the app talks to both
    downstream services; not a real retrieval pipeline."""
    question = payload.get("question", "")
    base = f"{CHROMA_URL}/api/v2/tenants/{TENANT}/databases/{DATABASE}"
    coll_id = getattr(app.state, "collection_id", None)
    context = ""
    if coll_id:
        r = requests.post(f"{base}/collections/{coll_id}/get", json={}, timeout=5)
        if r.status_code == 200:
            context = " ".join(r.json().get("documents", []))

    prompt = f"Context: {context}\nQuestion: {question}\nAnswer briefly:"
    try:
        r = requests.post(
            f"{OLLAMA_URL}/api/generate",
            json={"model": os.environ.get("OLLAMA_MODEL", "tinyllama"), "prompt": prompt, "stream": False},
            timeout=60,
        )
        answer = r.json().get("response", "") if r.status_code == 200 else f"ollama error {r.status_code}"
    except requests.RequestException as e:
        answer = f"ollama unreachable: {e}"

    return {"question": question, "context": context, "answer": answer}

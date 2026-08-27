#!/usr/bin/env bash
# Stand up the full three-tier stack (Ollama, ChromaDB, RAG app) on one
# user-defined bridge network, the way a real small deployment would look.
#
# Image tags/digests are pinned. ChromaDB's pinned digest matches the one
# already used and verified in the sibling vectordb/ component.
#
# Host ports 8000 and 8080 are already taken on this box (splunkd, java).
# The host-side forwards below use alternate ports; the containers' own
# internal binds are untouched (chroma still binds 0.0.0.0:8000 inside its
# own container, ollama still binds 0.0.0.0:11434 inside its own container).
set -euo pipefail

NET="lateral-net"
CHROMA_IMAGE="chromadb/chroma@sha256:1e0b73a187a28757c572acba508c46f48c9e8b0acaf5c20e6d95cdedce1acdf6"
OLLAMA_IMAGE="ollama/ollama:0.5.7@sha256:7e672211886f8bd4448a98ed577e26c816b9e8b052112860564afaa2c105800e"

CHROMA_HOST_PORT="${CHROMA_HOST_PORT:-18001}"
OLLAMA_HOST_PORT="${OLLAMA_HOST_PORT:-11434}"
APP_HOST_PORT="${APP_HOST_PORT:-19000}"

OLLAMA_MODEL="${OLLAMA_MODEL:-tinyllama}"

docker network inspect "$NET" >/dev/null 2>&1 || docker network create "$NET"

docker rm -f lateral-ollama lateral-chroma lateral-app >/dev/null 2>&1 || true

echo "== starting ollama =="
docker run -d --name lateral-ollama \
  --network "$NET" \
  -p "${OLLAMA_HOST_PORT}:11434" \
  "$OLLAMA_IMAGE"

echo "== starting chroma =="
docker run -d --name lateral-chroma \
  --network "$NET" \
  -p "${CHROMA_HOST_PORT}:8000" \
  "$CHROMA_IMAGE"

echo "== waiting for ollama =="
for i in $(seq 1 60); do
  if curl -sf "http://localhost:${OLLAMA_HOST_PORT}/api/tags" >/dev/null 2>&1; then
    echo "ollama ready after ${i}s"
    break
  fi
  sleep 1
done

echo "== waiting for chroma =="
for i in $(seq 1 60); do
  if curl -sf "http://localhost:${CHROMA_HOST_PORT}/api/v2/heartbeat" >/dev/null 2>&1; then
    echo "chroma ready after ${i}s"
    break
  fi
  sleep 1
done

echo "== pulling small model into ollama (${OLLAMA_MODEL}) =="
# Best effort - the chain does not depend on model quality or even a model
# being present at all (see rag_app.py error handling). If this pull is
# slow or fails, the RAG /query call will just report ollama's error, and
# every other step of the chain still stands on its own.
docker exec lateral-ollama ollama pull "$OLLAMA_MODEL" || \
  echo "WARNING: model pull failed or timed out, continuing without it"

echo "== building and starting the RAG app (attacker's foothold container) =="
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
"$SCRIPT_DIR/00-build-app-image.sh"

docker run -d --name lateral-app \
  --network "$NET" \
  -p "${APP_HOST_PORT}:9000" \
  -e CHROMA_URL="http://lateral-chroma:8000" \
  -e OLLAMA_URL="http://lateral-ollama:11434" \
  -e OLLAMA_MODEL="$OLLAMA_MODEL" \
  -e INTERNAL_API_TOKEN="INTERNAL_API_TOKEN_PLANTED_9f3a7c" \
  redteam/lateral-rag-app:latest

echo "== waiting for app =="
for i in $(seq 1 30); do
  if curl -sf "http://localhost:${APP_HOST_PORT}/health" >/dev/null 2>&1; then
    echo "app ready after ${i}s"
    exit 0
  fi
  sleep 1
done
echo "app did not become ready in time" >&2
docker logs lateral-app >&2
exit 1

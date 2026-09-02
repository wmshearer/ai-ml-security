#!/usr/bin/env bash
# Start ChromaDB with default configuration on the shared vectordb-net network.
# No auth env vars are set - this is the out-of-the-box state.
set -euo pipefail

IMAGE="chromadb/chroma@sha256:1e0b73a187a28757c572acba508c46f48c9e8b0acaf5c20e6d95cdedce1acdf6"
NET="vectordb-net"
# NOTE: host port 8000 was already bound by another service (splunkd) on the
# test box, so the host-side forward below uses 18000. The container's own
# internal default bind is still 0.0.0.0:8000 - see evidence/chroma/ for the
# in-container proof of the real default port.
HOST_PORT="${CHROMA_HOST_PORT:-18000}"

docker network inspect "$NET" >/dev/null 2>&1 || docker network create "$NET"

docker rm -f vectordb-chroma vectordb-chroma-client >/dev/null 2>&1 || true

docker run -d --name vectordb-chroma \
  --network "$NET" \
  -p "${HOST_PORT}:8000" \
  "$IMAGE"

docker run -d --name vectordb-chroma-client \
  --network "$NET" \
  curlimages/curl:8.11.0 sleep 3600

echo "Waiting for chroma to become ready..."
for i in $(seq 1 30); do
  if curl -sf "http://localhost:${HOST_PORT}/api/v2/heartbeat" >/dev/null 2>&1; then
    echo "chroma ready after ${i}s"
    exit 0
  fi
  sleep 1
done
echo "chroma did not become ready in time" >&2
docker logs vectordb-chroma >&2
exit 1

#!/usr/bin/env bash
# Start Qdrant with default configuration on the shared vectordb-net network.
# No QDRANT__SERVICE__API_KEY set - auth is opt-in and off by default.
set -euo pipefail

IMAGE="qdrant/qdrant@sha256:d122138f76868edba68d36cb0833139c1d1761f00f09e48e61f8314196e6a4c6"
NET="vectordb-net"
HTTP_PORT="${QDRANT_HTTP_PORT:-16333}"
GRPC_PORT="${QDRANT_GRPC_PORT:-16334}"

docker network inspect "$NET" >/dev/null 2>&1 || docker network create "$NET"

docker rm -f vectordb-qdrant vectordb-qdrant-client >/dev/null 2>&1 || true

docker run -d --name vectordb-qdrant \
  --network "$NET" \
  -p "${HTTP_PORT}:6333" \
  -p "${GRPC_PORT}:6334" \
  "$IMAGE"

docker run -d --name vectordb-qdrant-client \
  --network "$NET" \
  curlimages/curl:8.11.0 sleep 3600

echo "Waiting for qdrant to become ready..."
for i in $(seq 1 30); do
  if curl -sf "http://localhost:${HTTP_PORT}/" >/dev/null 2>&1; then
    echo "qdrant ready after ${i}s"
    exit 0
  fi
  sleep 1
done
echo "qdrant did not become ready in time" >&2
docker logs vectordb-qdrant >&2
exit 1

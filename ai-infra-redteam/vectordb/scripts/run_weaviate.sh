#!/usr/bin/env bash
# Start Weaviate with default configuration on the shared vectordb-net network.
# No AUTHENTICATION_APIKEY_ENABLED / AUTHENTICATION_OIDC_ENABLED set - Weaviate's
# own default is anonymous_access enabled when nothing is configured.
set -euo pipefail

IMAGE="semitechnologies/weaviate@sha256:5c62e5cbce4c48fc770abcee71099d9de32aad3b44d12299611f8135ee412362"
NET="vectordb-net"
# Host port 8080 is taken by another service on the test box; container's own
# internal default bind is still 0.0.0.0:8080 - see evidence/weaviate/ for proof.
HTTP_PORT="${WEAVIATE_HTTP_PORT:-18080}"
GRPC_PORT="${WEAVIATE_GRPC_PORT:-18081}"

docker network inspect "$NET" >/dev/null 2>&1 || docker network create "$NET"

docker rm -f vectordb-weaviate vectordb-weaviate-client >/dev/null 2>&1 || true

docker run -d --name vectordb-weaviate \
  --network "$NET" \
  -p "${HTTP_PORT}:8080" \
  -p "${GRPC_PORT}:50051" \
  "$IMAGE" \
  --host 0.0.0.0 --port 8080 --scheme http

docker run -d --name vectordb-weaviate-client \
  --network "$NET" \
  curlimages/curl:8.11.0 sleep 3600

echo "Waiting for weaviate to become ready..."
for i in $(seq 1 30); do
  if curl -sf "http://localhost:${HTTP_PORT}/v1/.well-known/ready" >/dev/null 2>&1; then
    echo "weaviate ready after ${i}s"
    exit 0
  fi
  sleep 1
done
echo "weaviate did not become ready in time" >&2
docker logs vectordb-weaviate >&2
exit 1

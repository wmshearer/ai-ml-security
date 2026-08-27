#!/usr/bin/env bash
# Start Triton with --model-control-mode=explicit (operator opt-in, not the
# default). Demonstrates: the same load/unload endpoint that NONE mode
# refuses now accepts unauthenticated load/unload requests.
set -euo pipefail

IMAGE="nvcr.io/nvidia/tritonserver:24.12-py3"
NET="designstudy-triton-net"
HOST_HTTP_PORT="${TRITON_HTTP_HOST_PORT:-12000}"
HOST_GRPC_PORT="${TRITON_GRPC_HOST_PORT:-12001}"
HOST_METRICS_PORT="${TRITON_METRICS_HOST_PORT:-12002}"
MODEL_REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/triton-models"

docker network inspect "$NET" >/dev/null 2>&1 || docker network create "$NET"

docker rm -f triton-designstudy-explicit >/dev/null 2>&1 || true

docker run -d --name triton-designstudy-explicit \
  --network "$NET" \
  -p "${HOST_HTTP_PORT}:8000" \
  -p "${HOST_GRPC_PORT}:8001" \
  -p "${HOST_METRICS_PORT}:8002" \
  -v "${MODEL_REPO}:/models:ro" \
  "$IMAGE" tritonserver --model-repository=/models --model-control-mode=explicit

echo "Waiting for Triton (EXPLICIT mode) to become ready..."
for i in $(seq 1 60); do
  if curl -sf "http://localhost:${HOST_HTTP_PORT}/v2/health/ready" >/dev/null 2>&1; then
    echo "triton ready after ${i}s on http://localhost:${HOST_HTTP_PORT}"
    echo "try: curl -X POST http://localhost:${HOST_HTTP_PORT}/v2/repository/models/identity_demo/load"
    exit 0
  fi
  sleep 1
done
echo "triton did not become ready in time" >&2
docker logs triton-designstudy-explicit >&2
exit 1

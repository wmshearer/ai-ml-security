#!/usr/bin/env bash
# Start Triton with default settings (model-control-mode NONE, the shipped
# default - no flag needed). Demonstrates: the model load/unload endpoint is
# refused in this mode.
set -euo pipefail

IMAGE="nvcr.io/nvidia/tritonserver:24.12-py3"
NET="designstudy-triton-net"
HOST_HTTP_PORT="${TRITON_HTTP_HOST_PORT:-12000}"
HOST_GRPC_PORT="${TRITON_GRPC_HOST_PORT:-12001}"
HOST_METRICS_PORT="${TRITON_METRICS_HOST_PORT:-12002}"
MODEL_REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/triton-models"

docker network inspect "$NET" >/dev/null 2>&1 || docker network create "$NET"

docker rm -f triton-designstudy-none >/dev/null 2>&1 || true

docker run -d --name triton-designstudy-none \
  --network "$NET" \
  -p "${HOST_HTTP_PORT}:8000" \
  -p "${HOST_GRPC_PORT}:8001" \
  -p "${HOST_METRICS_PORT}:8002" \
  -v "${MODEL_REPO}:/models:ro" \
  "$IMAGE" tritonserver --model-repository=/models

echo "Waiting for Triton (NONE mode) to become ready..."
for i in $(seq 1 60); do
  if curl -sf "http://localhost:${HOST_HTTP_PORT}/v2/health/ready" >/dev/null 2>&1; then
    echo "triton ready after ${i}s on http://localhost:${HOST_HTTP_PORT}"
    exit 0
  fi
  sleep 1
done
echo "triton did not become ready in time" >&2
docker logs triton-designstudy-none >&2
exit 1

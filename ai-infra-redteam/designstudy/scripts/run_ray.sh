#!/usr/bin/env bash
# Start Ray in a container with default settings (no RAY_AUTH_MODE set).
# Demonstrates: dashboard/job submission API reachable with zero credentials.
set -euo pipefail

IMAGE="rayproject/ray:2.58.0-py311"
NET="designstudy-ray-net"
HOST_PORT="${RAY_DASHBOARD_HOST_PORT:-12265}"

docker network inspect "$NET" >/dev/null 2>&1 || docker network create "$NET"

docker rm -f ray-designstudy >/dev/null 2>&1 || true

docker run -d --name ray-designstudy \
  --network "$NET" \
  -p "${HOST_PORT}:8265" \
  "$IMAGE" ray start --head --dashboard-host=0.0.0.0 --block

echo "Waiting for Ray dashboard to become ready..."
for i in $(seq 1 30); do
  if curl -sf "http://localhost:${HOST_PORT}/api/version" >/dev/null 2>&1; then
    echo "ray ready after ${i}s, dashboard on http://localhost:${HOST_PORT}"
    exit 0
  fi
  sleep 1
done
echo "ray did not become ready in time" >&2
docker logs ray-designstudy >&2
exit 1

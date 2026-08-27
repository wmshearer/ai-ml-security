#!/usr/bin/env bash
# Start Ray in a container with RAY_AUTH_MODE=token set (the opt-in auth
# feature added in Ray 2.52.0, off by default). Demonstrates the contrast:
# the same job-submission API now rejects unauthenticated requests and
# accepts requests carrying the bearer token.
set -euo pipefail

IMAGE="rayproject/ray:2.58.0-py311"
NET="designstudy-ray-net"
HOST_PORT="${RAY_AUTHMODE_DASHBOARD_HOST_PORT:-12266}"
TOKEN="${RAY_DEMO_TOKEN:-designstudy-demo-token-$(openssl rand -hex 16)}"

docker network inspect "$NET" >/dev/null 2>&1 || docker network create "$NET"

docker rm -f ray-designstudy-authmode >/dev/null 2>&1 || true

docker run -d --name ray-designstudy-authmode \
  --network "$NET" \
  -p "${HOST_PORT}:8265" \
  -e RAY_AUTH_MODE=token \
  -e RAY_AUTH_TOKEN="$TOKEN" \
  "$IMAGE" ray start --head --dashboard-host=0.0.0.0 --block

echo "Waiting for Ray (auth mode) dashboard to become ready..."
for i in $(seq 1 30); do
  if curl -s "http://localhost:${HOST_PORT}/api/jobs/" | grep -qi "unauthorized"; then
    echo "ray (auth mode) ready after ${i}s, dashboard on http://localhost:${HOST_PORT}"
    echo "demo token: ${TOKEN}"
    echo "try: curl -H \"Authorization: Bearer ${TOKEN}\" http://localhost:${HOST_PORT}/api/jobs/"
    exit 0
  fi
  sleep 1
done
echo "ray (auth mode) did not become ready in time" >&2
docker logs ray-designstudy-authmode >&2
exit 1

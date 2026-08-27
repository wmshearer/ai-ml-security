#!/usr/bin/env bash
# Start Milvus standalone (+ its required etcd and minio dependencies) with
# default configuration on the shared vectordb-net network. No auth env vars
# set for Milvus - authorization is opt-in via common.security.authorizationEnabled.
set -euo pipefail

NET="vectordb-net"
ETCD_IMAGE="quay.io/coreos/etcd@sha256:52f17f7e56e4f7239f0320dbfcbcc24721163d7d78ae710b466af3254ccf6366"
MINIO_IMAGE="minio/minio@sha256:391d1d45fdbe79944cb6de9337b073864bb9ee38c4c24280bfb39572e925af08"
MILVUS_IMAGE="milvusdb/milvus@sha256:49371c30af46b1013e4d3e0b980e691d81376d69cdbe1b372725baf1d7255862"

GRPC_PORT="${MILVUS_GRPC_PORT:-19530}"
METRICS_PORT="${MILVUS_METRICS_PORT:-9091}"

docker network inspect "$NET" >/dev/null 2>&1 || docker network create "$NET"

docker rm -f vectordb-milvus-standalone vectordb-milvus-etcd vectordb-milvus-minio vectordb-milvus-client >/dev/null 2>&1 || true

echo "starting etcd..."
docker run -d --name vectordb-milvus-etcd \
  --network "$NET" --network-alias etcd \
  -e ETCD_AUTO_COMPACTION_MODE=revision \
  -e ETCD_AUTO_COMPACTION_RETENTION=1000 \
  -e ETCD_QUOTA_BACKEND_BYTES=4294967296 \
  -e ETCD_SNAPSHOT_COUNT=50000 \
  "$ETCD_IMAGE" \
  etcd -advertise-client-urls=http://etcd:2379 -listen-client-urls http://0.0.0.0:2379 --data-dir /etcd

echo "starting minio..."
docker run -d --name vectordb-milvus-minio \
  --network "$NET" --network-alias minio \
  -e MINIO_ACCESS_KEY=minioadmin \
  -e MINIO_SECRET_KEY=minioadmin \
  "$MINIO_IMAGE" \
  minio server /minio_data --console-address ":9001"

echo "waiting for etcd/minio to settle..."
sleep 8

echo "starting milvus standalone..."
docker run -d --name vectordb-milvus-standalone \
  --network "$NET" \
  --security-opt seccomp:unconfined \
  -e MINIO_REGION=us-east-1 \
  -e ETCD_ENDPOINTS=etcd:2379 \
  -e MINIO_ADDRESS=minio:9000 \
  -p "${GRPC_PORT}:19530" \
  -p "${METRICS_PORT}:9091" \
  "$MILVUS_IMAGE" \
  milvus run standalone

docker run -d --name vectordb-milvus-client \
  --network "$NET" \
  curlimages/curl:8.11.0 sleep 3600

echo "Waiting for milvus standalone to become healthy (can take 60-90s)..."
for i in $(seq 1 120); do
  if curl -sf "http://localhost:${METRICS_PORT}/healthz" >/dev/null 2>&1; then
    echo "milvus ready after ${i}s"
    exit 0
  fi
  sleep 1
done
echo "milvus did not become ready in time" >&2
docker logs --tail 100 vectordb-milvus-standalone >&2
exit 1

#!/usr/bin/env bash
# Plant two "tenants" worth of synthetic secret data directly in ChromaDB,
# simulating a real deployment where a second team/customer/project shares
# the same vector DB instance under a different tenant. All values are
# obviously fake, per the project's hard constraints.
set -euo pipefail

CHROMA_HOST_PORT="${CHROMA_HOST_PORT:-18001}"
BASE="http://localhost:${CHROMA_HOST_PORT}/api/v2"

echo "== creating tenant_a / db_a =="
curl -s -X POST "$BASE/tenants" -H 'Content-Type: application/json' \
  -d '{"name":"tenant_a"}' ; echo
curl -s -X POST "$BASE/tenants/tenant_a/databases" -H 'Content-Type: application/json' \
  -d '{"name":"db_a"}' ; echo

echo "== creating tenant_b / db_b =="
curl -s -X POST "$BASE/tenants" -H 'Content-Type: application/json' \
  -d '{"name":"tenant_b"}' ; echo
curl -s -X POST "$BASE/tenants/tenant_b/databases" -H 'Content-Type: application/json' \
  -d '{"name":"db_b"}' ; echo

echo "== creating collection secrets_a in tenant_a/db_a =="
COLL_A=$(curl -s -X POST "$BASE/tenants/tenant_a/databases/db_a/collections" \
  -H 'Content-Type: application/json' -d '{"name":"secrets_a"}' | python3 -c 'import sys,json; print(json.load(sys.stdin)["id"])')
echo "collection A id: $COLL_A"

echo "== creating collection secrets_b in tenant_b/db_b =="
COLL_B=$(curl -s -X POST "$BASE/tenants/tenant_b/databases/db_b/collections" \
  -H 'Content-Type: application/json' -d '{"name":"secrets_b"}' | python3 -c 'import sys,json; print(json.load(sys.stdin)["id"])')
echo "collection B id: $COLL_B"

echo "== seeding secrets_a =="
curl -s -X POST "$BASE/tenants/tenant_a/databases/db_a/collections/${COLL_A}/add" \
  -H 'Content-Type: application/json' \
  -d '{"ids":["doc-a-1"],"documents":["LATERAL_TENANT_A_SECRET_VALUE_71bd2f"],"embeddings":[[0.1,0.2,0.3,0.4]]}' ; echo

echo "== seeding secrets_b =="
curl -s -X POST "$BASE/tenants/tenant_b/databases/db_b/collections/${COLL_B}/add" \
  -H 'Content-Type: application/json' \
  -d '{"ids":["doc-b-1"],"documents":["LATERAL_TENANT_B_SECRET_VALUE_ae930c"],"embeddings":[[0.9,0.8,0.7,0.6]]}' ; echo

# Persist the collection UUIDs so the enumeration step (run from inside the
# app container, which does NOT otherwise know these tenants exist) can be
# scripted deterministically for evidence capture. In a real chain the
# attacker would have to find these UUIDs some other way (logging leak,
# cache, IDOR) - see FINDINGS.md for that caveat, reused from vectordb/.
mkdir -p "$(dirname "$0")/../evidence"
{
  echo "COLLECTION_A_ID=${COLL_A}"
  echo "COLLECTION_B_ID=${COLL_B}"
} > "$(dirname "$0")/../evidence/planted-collection-ids.txt"

echo "== done. Collection IDs written to evidence/planted-collection-ids.txt =="

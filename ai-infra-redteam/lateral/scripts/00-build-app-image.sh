#!/usr/bin/env bash
# Build the RAG app image used as the attacker's foothold container.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LATERAL_ROOT="$(dirname "$SCRIPT_DIR")"

docker build -t redteam/lateral-rag-app:latest "$LATERAL_ROOT/app"

#!/usr/bin/env bash
# Stop and remove every container and network this component created.
set -uo pipefail

docker rm -f lateral-ollama lateral-chroma lateral-app >/dev/null 2>&1
docker network rm lateral-net >/dev/null 2>&1

echo "cleanup done. Remaining lateral-* resources (should be empty):"
docker ps -a --filter "name=lateral-"
docker network ls --filter "name=lateral-net"

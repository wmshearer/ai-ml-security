#!/bin/bash
# Demonstrates Docker's documented (and widely misunderstood) bridge network
# behavior: containers on the same user-defined bridge network can reach
# ALL of each other's ports, published or not. Containers on different
# user-defined networks cannot reach each other at all.
#
# Cleans up every network/container it creates, even on failure.
set -uo pipefail
cd "$(dirname "$0")/.."
EV=evidence
IMG=redteam/capcheck:latest
mkdir -p "$EV"

cleanup() {
  docker rm -f netA-listener >/dev/null 2>&1
  docker network rm redteam-net-a redteam-net-b >/dev/null 2>&1
}
trap cleanup EXIT

cleanup # in case a previous run left state behind

echo "[1/3] Create two isolated user-defined bridge networks"
{
  echo "\$ docker network create redteam-net-a"
  docker network create redteam-net-a
  echo "\$ docker network create redteam-net-b"
  docker network create redteam-net-b
} > "$EV/11-network-isolation-setup.txt" 2>&1

echo "[2/3] Start a listener on net-a with an UNPUBLISHED port (no -p flag)"
{
  docker network ls | grep redteam
  echo
  echo "\$ docker run -d --rm --name netA-listener --network redteam-net-a $IMG sh -c 'while true; do (echo secret-service-on-9999) | nc -l -p 9999; done'"
  docker run -d --rm --name netA-listener --network redteam-net-a "$IMG" sh -c 'while true; do (echo "secret-service-on-9999") | nc -l -p 9999; done'
  sleep 1
  echo "\$ docker port netA-listener  (expect EMPTY - nothing published to host)"
  docker port netA-listener
  echo "(exit code: $?, empty output confirmed = no published ports)"
  echo
  LISTENER_IP=$(docker inspect -f '{{(index .NetworkSettings.Networks "redteam-net-a").IPAddress}}' netA-listener)
  echo "listener IP on net-a: $LISTENER_IP"
  echo "$LISTENER_IP" > "$EV/.listener_ip"
} > "$EV/12-network-listener-setup.txt" 2>&1

LISTENER_IP=$(cat "$EV/.listener_ip")
rm -f "$EV/.listener_ip"

echo "[3/3] Reachability tests: same network vs different network vs host"
{
  echo "=== Test A: same-network client reaches the UNPUBLISHED port (redteam-net-a) ==="
  echo "\$ docker run --rm --network redteam-net-a $IMG sh -c 'echo | nc -w 2 $LISTENER_IP 9999'"
  docker run --rm --network redteam-net-a "$IMG" sh -c "echo | nc -w 2 $LISTENER_IP 9999"
  echo "(exit code: $?)"
  echo
  echo "=== Test B: DIFFERENT-network client (redteam-net-b) attempts to reach same target IP/port ==="
  echo "\$ docker run --rm --network redteam-net-b $IMG sh -c 'echo | nc -w 2 -v $LISTENER_IP 9999; echo exit:\$?'"
  docker run --rm --network redteam-net-b "$IMG" sh -c "echo | nc -w 2 -v $LISTENER_IP 9999; echo exit:\$?"
  echo
  echo "=== Test C: from the HOST, confirm the unpublished port is NOT reachable ==="
  echo "\$ curl -s --max-time 2 http://127.0.0.1:9999 ; echo host-curl-exit:\$?"
  curl -s --max-time 2 http://127.0.0.1:9999; echo "host-curl-exit:$?"
} > "$EV/13-network-isolation-tests.txt" 2>&1

echo "Done. See evidence/11-*.txt through evidence/13-*.txt"
echo "Cleaning up test containers and networks..."

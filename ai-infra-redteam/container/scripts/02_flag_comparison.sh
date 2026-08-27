#!/bin/bash
# Measures what each dangerous docker run flag actually grants, against a
# default-container baseline. Builds a small local image with libcap2-bin
# so capability sets can be decoded, not just shown as hex.
#
# Safe: no writes to host filesystems. --privileged device access is
# demonstrated with a read-only dd of the first bytes of the host disk.
set -uo pipefail
cd "$(dirname "$0")/.."
EV=evidence
IMG=redteam/capcheck:latest
mkdir -p "$EV"

echo "[1/6] Build the capability-check image"
docker build -t "$IMG" -f scripts/Dockerfile.capcheck scripts/ > "$EV/00-capcheck-image-build.txt" 2>&1

run_cap_check() {
  local label="$1"; shift
  echo "=== $label ==="
  echo "\$ docker run --rm $* $IMG sh -c '<decode CapEff>'"
  docker run --rm "$@" "$IMG" sh -c '
    echo "--- /proc/self/status Cap lines ---";
    grep -E "^Cap(Inh|Prm|Eff|Bnd|Amb)" /proc/self/status;
    echo;
    EFF=$(grep "^CapEff" /proc/self/status | awk "{print \$2}");
    echo "--- decoded CapEff ($EFF) ---";
    capsh --decode=$EFF;
  '
  echo
}

echo "[2/6] Capability comparison: default, --privileged, and each --cap-add"
{
  run_cap_check "DEFAULT (no extra flags)"
  run_cap_check "--privileged" --privileged
  run_cap_check "--cap-add=SYS_ADMIN" --cap-add=SYS_ADMIN
  run_cap_check "--cap-add=SYS_PTRACE" --cap-add=SYS_PTRACE
  run_cap_check "--cap-add=DAC_READ_SEARCH" --cap-add=DAC_READ_SEARCH
} > "$EV/06-capability-comparison.txt" 2>&1

echo "[3/6] Device visibility: default vs --privileged"
{
  echo "=== DEFAULT container: host devices visible? ==="
  docker run --rm "$IMG" sh -c 'ls /dev; echo "---lsblk---"; lsblk 2>&1; echo "---fdisk---"; fdisk -l 2>&1'
  echo
  echo "=== --privileged container: host devices visible? ==="
  docker run --rm --privileged "$IMG" sh -c 'ls /dev; echo "---lsblk---"; lsblk; echo "---fdisk---"; fdisk -l 2>&1'
} > "$EV/07-privileged-device-visibility.txt" 2>&1

echo "[4/6] Device NODE presence + read-only proof of raw disk access under --privileged"
{
  echo "=== DEFAULT: does /dev/nvme0n1 device node exist? ==="
  docker run --rm "$IMG" sh -c 'echo "/dev/nvme0n1: $(test -e /dev/nvme0n1 && echo PRESENT || echo ABSENT)"; echo "/dev/mem: $(test -e /dev/mem && echo PRESENT || echo ABSENT)"; echo "/dev/kmsg: $(test -e /dev/kmsg && echo PRESENT || echo ABSENT)"'
  echo
  echo "=== --privileged: device node presence + permissions ==="
  docker run --rm --privileged "$IMG" sh -c 'echo "/dev/nvme0n1: $(test -e /dev/nvme0n1 && echo PRESENT || echo ABSENT)"; echo "/dev/mem: $(test -e /dev/mem && echo PRESENT || echo ABSENT)"; echo "/dev/kmsg: $(test -e /dev/kmsg && echo PRESENT || echo ABSENT)"; ls -la /dev/nvme0n1 /dev/mem /dev/kmsg 2>&1'
  echo
  echo "=== Read-only proof: first 64 bytes of host disk from --privileged (no write performed) ==="
  docker run --rm --privileged "$IMG" sh -c 'dd if=/dev/nvme0n1 bs=64 count=1 2>/dev/null | od -A x -t x1z; echo "dd+od exit: $?"'
} > "$EV/08-privileged-device-node-access.txt" 2>&1

echo "[5/6] Docker socket mount: enumerate host containers/version, no escape performed"
{
  echo "=== \$ docker run --rm -v /var/run/docker.sock:/var/run/docker.sock $IMG curl -s --unix-socket /var/run/docker.sock http://localhost/version"
  docker run --rm -v /var/run/docker.sock:/var/run/docker.sock "$IMG" curl -s --unix-socket /var/run/docker.sock http://localhost/version
  echo; echo
  echo "=== \$ docker run --rm -v /var/run/docker.sock:/var/run/docker.sock $IMG curl -s --unix-socket /var/run/docker.sock 'http://localhost/containers/json?all=true'"
  docker run --rm -v /var/run/docker.sock:/var/run/docker.sock "$IMG" curl -s --unix-socket /var/run/docker.sock 'http://localhost/containers/json?all=true'
  echo; echo
  echo "NOTE: full host root is a documented, trivial next step from here and is NOT performed."
} > "$EV/09-docker-socket-mount.txt" 2>&1

echo "[6/6] --pid=host process visibility"
{
  echo "=== DEFAULT: process visibility (own PID namespace) ==="
  docker run --rm "$IMG" ps aux
  echo
  echo "=== --pid=host: process visibility ==="
  docker run --rm --pid=host "$IMG" ps aux | head -20
  echo "..."
  echo "(total lines):"
  docker run --rm --pid=host "$IMG" ps aux | wc -l
} > "$EV/10-pid-host-comparison.txt" 2>&1

echo "Done. See evidence/06-*.txt through evidence/10-*.txt"

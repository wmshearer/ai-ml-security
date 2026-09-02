#!/bin/bash
# Demonstrates that NVIDIA Container Toolkit GPU passthrough via --gpus all
# does NOT require --privileged, and measures exactly what it grants
# (device nodes only) versus what --privileged grants (full capability set
# plus every host device).
#
# The CUDA base image tag must match the host driver's supported CUDA
# version. Override with GPU_IMAGE=... if the host driver changes.
set -uo pipefail
cd "$(dirname "$0")/.."
EV=evidence
GPUIMG="${GPU_IMAGE:-nvidia/cuda:12.4.1-base-ubuntu22.04}"
mkdir -p "$EV"

echo "[1/2] GPU container without --privileged"
{
  echo "=== Host driver check (for reference) ==="
  echo "\$ nvidia-smi | head -3"
  nvidia-smi | head -3
  echo
  echo "=== GPU container WITHOUT --privileged: nvidia-smi via --gpus all ==="
  echo "\$ docker run --rm --gpus all $GPUIMG nvidia-smi"
  docker run --rm --gpus all "$GPUIMG" nvidia-smi
  echo "(exit code: $?)"
} > "$EV/14-gpu-container-nonprivileged.txt" 2>&1

echo "[2/2] Capability set and device access comparison"
{
  echo "=== Capability set of --gpus all container (no --privileged) ==="
  docker run --rm --gpus all "$GPUIMG" sh -c '
    grep -E "^Cap(Inh|Prm|Eff|Bnd|Amb)" /proc/self/status;
  '
  echo
  echo "Compare CapEff hex above against evidence/06-capability-comparison.txt DEFAULT and --privileged rows."
  echo
  echo "=== Device nodes visible inside --gpus all container (NOT --privileged) ==="
  docker run --rm --gpus all "$GPUIMG" sh -c 'ls -la /dev | grep -i nvidia; echo "---other host devices---"; echo "/dev/nvme0n1: $(test -e /dev/nvme0n1 && echo PRESENT || echo ABSENT)"; echo "/dev/mem: $(test -e /dev/mem && echo PRESENT || echo ABSENT)"; echo "/dev/kmsg: $(test -e /dev/kmsg && echo PRESENT || echo ABSENT)"'
} > "$EV/15-gpu-capability-and-device-comparison.txt" 2>&1

echo "Done. See evidence/14-*.txt and evidence/15-*.txt"

#!/bin/bash
# Runs all four evidence-gathering scripts in order. Requires Docker.
set -euo pipefail
cd "$(dirname "$0")"

./01_release_agent_check.sh
./02_flag_comparison.sh
./03_network_isolation.sh
./04_gpu_comparison.sh

echo
echo "All done. Evidence written to ../evidence/"

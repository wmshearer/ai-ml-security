#!/usr/bin/env bash
# Remove every container and network this component starts. Safe to run
# even if some of them were never started.
set -uo pipefail

for c in ray-designstudy ray-designstudy-authmode \
         triton-designstudy-none triton-designstudy-explicit; do
  docker rm -f "$c" >/dev/null 2>&1 && echo "removed container: $c"
done

for n in designstudy-ray-net designstudy-triton-net; do
  docker network rm "$n" >/dev/null 2>&1 && echo "removed network: $n"
done

echo "designstudy cleanup done."

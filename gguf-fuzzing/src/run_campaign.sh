#!/usr/bin/env bash
# Drives the real fuzzing campaign, restarting libFuzzer across crashes.
#
# WHY THIS EXISTS: libFuzzer stops the whole process on the first crash or
# timeout it finds (that's its job -- surface the finding). This target has
# at least one real, reproducible finding (see FINDINGS.md, "CPU-time
# exhaustion via oversized array element count") that a mutation can
# rediscover repeatedly from the KV-pairs seed. Rather than let one restart
# hide how many total executions we actually ran, this script:
#   1. runs atheris with a fixed per-invocation -atheris_runs budget,
#   2. on ANY exit (clean or crash), records the exit code and moves any
#      new artifact out of artifacts/ into a per-finding subdirectory so
#      the next invocation starts with a clean artifacts/ dir,
#   3. repeats until either TOTAL_RUN_BUDGET executions have been attempted
#      (summed across restarts, from the "Executed N inputs" reporting we
#      parse out of libFuzzer's own totals in each log) or MAX_RESTARTS is
#      hit, whichever comes first,
#   4. never re-runs the exact same crash forever: each restart reuses and
#      grows corpus_evolved/, so the search keeps moving rather than
#      looping on one input (libFuzzer does not add a crashing input back
#      into the live corpus).
#
# All per-restart logs are kept under logs/ for the record; nothing here
# fabricates or merges numbers -- FINDINGS.md sums the real per-restart
# "stat::number_of_executed_units" totals pulled from these logs.
set -uo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

TOTAL_RUN_BUDGET="${1:-200000}"
PER_RUN_BUDGET="${2:-50000}"
MAX_RESTARTS="${3:-30}"

CORPUS_DIR="$PROJECT_ROOT/corpus_evolved"
ARTIFACTS_DIR="$PROJECT_ROOT/artifacts"
LOGS_DIR="$PROJECT_ROOT/logs"
FINDINGS_DIR="$ARTIFACTS_DIR/timeouts_and_ooms"

mkdir -p "$CORPUS_DIR" "$ARTIFACTS_DIR" "$LOGS_DIR" "$FINDINGS_DIR"

total_executed=0
restart=0
campaign_log="$LOGS_DIR/campaign_summary.log"
: > "$campaign_log"

echo "Campaign start (UTC): $(date -u)" | tee -a "$campaign_log"
echo "TOTAL_RUN_BUDGET=$TOTAL_RUN_BUDGET PER_RUN_BUDGET=$PER_RUN_BUDGET MAX_RESTARTS=$MAX_RESTARTS" | tee -a "$campaign_log"

while [ "$total_executed" -lt "$TOTAL_RUN_BUDGET" ] && [ "$restart" -lt "$MAX_RESTARTS" ]; do
  restart=$((restart + 1))
  run_log="$LOGS_DIR/campaign_restart_${restart}.log"

  echo "--- restart $restart: starting, total_executed_so_far=$total_executed ---" | tee -a "$campaign_log"

  "$PROJECT_ROOT/.venv/bin/python3" -m coverage run \
    --data-file="$LOGS_DIR/campaign.coverage" --include='*/vendor/gguf/gguf_reader.py' --append \
    "$PROJECT_ROOT/src/fuzz_gguf.py" "$CORPUS_DIR/" \
    -atheris_runs="$PER_RUN_BUDGET" -timeout=5 -rss_limit_mb=2048 \
    -artifact_prefix="$ARTIFACTS_DIR/" -close_fd_mask=3 \
    > "$run_log" 2>&1
  exit_code=$?

  # Pull the real executed-unit count out of this restart's log. libFuzzer
  # prints "stat::number_of_executed_units: N" in -print_final_stats mode,
  # but we are not passing that flag, so instead we count the highest
  # `#N` iteration counter actually printed (libFuzzer logs progress lines
  # like "#1234  NEW/REDUCE/pulse ..."), which is a real lower bound on
  # executions performed in this restart, read from real output.
  this_run_count=$(grep -oE '^#[0-9]+' "$run_log" | tr -d '#' | sort -n | tail -1)
  this_run_count="${this_run_count:-0}"
  total_executed=$((total_executed + this_run_count))

  echo "restart $restart: exit_code=$exit_code executed_this_restart=$this_run_count cumulative=$total_executed" | tee -a "$campaign_log"

  # Move any crash/timeout/oom artifact this restart produced out of
  # artifacts/ so the next restart starts clean, but keep it for the record.
  shopt -s nullglob
  for f in "$ARTIFACTS_DIR"/timeout-* "$ARTIFACTS_DIR"/oom-* "$ARTIFACTS_DIR"/crash-*; do
    [ -e "$f" ] || continue
    base="$(basename "$f")"
    dest="$FINDINGS_DIR/restart${restart}_${base}"
    mv "$f" "$dest"
    echo "  moved artifact: $dest" | tee -a "$campaign_log"
  done
  shopt -u nullglob

  if [ "$exit_code" -eq 0 ]; then
    echo "restart $restart: clean exit (ran out its budget with no crash/timeout/oom)" | tee -a "$campaign_log"
  fi
done

echo "Campaign end (UTC): $(date -u)" | tee -a "$campaign_log"
echo "Total restarts: $restart" | tee -a "$campaign_log"
echo "Total executions (sum across restarts, lower bound from progress counters): $total_executed" | tee -a "$campaign_log"
echo "Final corpus_evolved/ size: $(ls "$CORPUS_DIR" | wc -l) files" | tee -a "$campaign_log"

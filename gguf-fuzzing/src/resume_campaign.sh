#!/usr/bin/env bash
# Resumes the campaign started by run_campaign.sh, continuing restart
# numbering and cumulative execution totals from where a prior invocation
# left off. See run_campaign.sh's header comment for the overall design
# rationale (why restarts happen at all: this target has a real,
# reproducible CPU-time-exhaustion finding that libFuzzer's own crash
# handling stops the process on every time it's rediscovered).
set -uo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

TOTAL_RUN_BUDGET="${1:-200000}"
PER_RUN_BUDGET="${2:-50000}"
MAX_RESTARTS="${3:-60}"
START_RESTART="${4:-12}"
START_CUMULATIVE="${5:-61913}"

CORPUS_DIR="$PROJECT_ROOT/corpus_evolved"
ARTIFACTS_DIR="$PROJECT_ROOT/artifacts"
LOGS_DIR="$PROJECT_ROOT/logs"
FINDINGS_DIR="$ARTIFACTS_DIR/timeouts_and_ooms"

mkdir -p "$CORPUS_DIR" "$ARTIFACTS_DIR" "$LOGS_DIR" "$FINDINGS_DIR"

total_executed="$START_CUMULATIVE"
restart=$((START_RESTART - 1))
campaign_log="$LOGS_DIR/campaign_summary.log"

echo "Campaign RESUME (UTC): $(date -u)" | tee -a "$campaign_log"
echo "Resuming from restart=$START_RESTART cumulative=$START_CUMULATIVE TOTAL_RUN_BUDGET=$TOTAL_RUN_BUDGET" | tee -a "$campaign_log"

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

  this_run_count=$(grep -oE '^#[0-9]+' "$run_log" | tr -d '#' | sort -n | tail -1)
  this_run_count="${this_run_count:-0}"
  total_executed=$((total_executed + this_run_count))

  echo "restart $restart: exit_code=$exit_code executed_this_restart=$this_run_count cumulative=$total_executed" | tee -a "$campaign_log"

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

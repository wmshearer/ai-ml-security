#!/usr/bin/env bash
# Start the recording proxy in the foreground on port 11435, in front of the
# real Ollama server on 11434. Ctrl-C to stop. Run this in its own terminal
# (or background it) before running scripts/04_run_case.py or 00_smoke_test.py.
set -euo pipefail
cd "$(dirname "$0")/.."
exec .venv/bin/uvicorn agentic_injection.proxy:app --app-dir src --host 127.0.0.1 --port 11435 --log-level info

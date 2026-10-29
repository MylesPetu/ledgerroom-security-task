#!/bin/bash
set -uo pipefail
APP_DIR="${LEDGERROOM_APP_DIR:-/app}"
TEST_DIR="${LEDGERROOM_TEST_DIR:-/tests}"
LOG_DIR="${LEDGERROOM_LOG_DIR:-/logs/verifier}"
mkdir -p "$LOG_DIR"
printf '0\n' > "$LOG_DIR/reward.txt"
if python3 "$TEST_DIR/verify.py" --app "$APP_DIR"; then
    printf '1\n' > "$LOG_DIR/reward.txt"
fi

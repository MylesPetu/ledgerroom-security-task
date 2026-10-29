#!/bin/bash
set -euo pipefail
APP_DIR="${LEDGERROOM_APP_DIR:-/app}"
SOLUTION_DIR="${LEDGERROOM_SOLUTION_DIR:-/solution}"
cp "$SOLUTION_DIR/policy.py" "$APP_DIR/policy.py"
cp "$SOLUTION_DIR/service.py" "$APP_DIR/service.py"

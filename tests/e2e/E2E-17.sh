#!/usr/bin/env bash
# Test-ID: E2E-17
set -Eeuo pipefail
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/../evaluation/shell.sh"
evaluation_scenario E2E-17

# Python coordinates ptrace or samples monotonic timestamps within one process.
python3 "$EVAL_HELPERS/E2E-17.py"

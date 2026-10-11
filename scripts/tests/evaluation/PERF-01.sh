#!/usr/bin/env bash
# Test-ID: PERF-01
set -Eeuo pipefail
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/shell.sh"
evaluation_scenario PERF-01

# Python coordinates ptrace or samples monotonic timestamps within one process.
python3 "$EVAL_HELPERS/PERF-01.py"

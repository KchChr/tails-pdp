#!/usr/bin/env bash
# Test-ID: PERF-02
set -Eeuo pipefail
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/shell.sh"
evaluation_scenario PERF-02

# Python coordinates ptrace or samples monotonic timestamps within one process.
python3 "$EVAL_HELPERS/PERF-02.py"

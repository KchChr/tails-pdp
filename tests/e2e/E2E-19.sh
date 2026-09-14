#!/usr/bin/env bash
# Test-ID: E2E-19 — FD revocation caused only by a time boundary.
set -Eeuo pipefail
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/../evaluation/shell.sh"
evaluation_scenario E2E-19
python3 "$EVAL_HELPERS/dynamic_fd.py" time

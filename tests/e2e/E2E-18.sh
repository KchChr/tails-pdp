#!/usr/bin/env bash
# Test-ID: E2E-18 — FD revocation caused only by an attribute activation.
set -Eeuo pipefail
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/../evaluation/shell.sh"
evaluation_scenario E2E-18
python3 "$EVAL_HELPERS/dynamic_fd.py" attribute

#!/usr/bin/env bash
# Runs the per-ID Bash scenarios with isolated runtime fixtures and saved reports.
set -Eeuo pipefail
PROJECT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
exec python3 "$PROJECT_ROOT/tests/evaluation/run.py" "$@"

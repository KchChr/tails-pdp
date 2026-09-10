#!/usr/bin/env bash
# Test-ID: E2E-16
set -Eeuo pipefail
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/../evaluation/shell.sh"
evaluation_scenario E2E-16

start_probe multi
policy_and_wait test deny '' tails-fd-probe
check_probe_results '[true, true, true]'

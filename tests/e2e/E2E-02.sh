#!/usr/bin/env bash
# Test-ID: E2E-02
set -Eeuo pipefail

readonly SCENARIO_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$SCENARIO_DIR/lib.sh"
require_e2e_environment

step "[E2E-02] Leerer Policystand erlaubt den Dateizugriff"
wait_for_access allow "Ausgangszustand ohne Policies"

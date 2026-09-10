#!/usr/bin/env bash
# Test-ID: E2E-08
set -Eeuo pipefail

readonly SCENARIO_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$SCENARIO_DIR/lib.sh"
require_e2e_environment

step "[E2E-08] Ungültiges Update lässt die letzte gültige Generation aktiv"
install_policy "60-rollback" <<EOF
policy "e2e rollback deny"
deny
    action == "file_open";
    resource.path == "$TARGET_FILE";
EOF
wait_for_access deny "gültige Rollback-Ausgangspolicy"

# Das fehlende Semikolon macht das Update ungültig. Die zuvor aktive
# Deny-Generation muss bestehen bleiben und die Runtime weiterlaufen.
install_policy "60-rollback" <<EOF
policy "e2e rollback invalid"
deny
    action == "file_open"
    resource.path == "$TARGET_FILE";
EOF
wait_for_log "previous generation remains active" "Rollback nach ungültiger Policy"
wait_for_access deny "letzte gültige Generation nach Parserfehler"
remove_policy_and_wait "60-rollback"
wait_for_access allow "Entfernen des ungültigen Policy-Stands"

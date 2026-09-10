#!/usr/bin/env bash
set -Eeuo pipefail

readonly SCENARIO_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$SCENARIO_DIR/lib.sh"
require_e2e_environment

step "[E2E-03] Statische Deny-Policy und Policy-Lebenszyklus"
install_policy "10-static-deny" <<EOF
policy "e2e static deny"
deny
    action == "file_open";
    resource.path == "$TARGET_FILE";
EOF
wait_for_access deny "statische Deny-Policy"
remove_policy_and_wait "10-static-deny"
wait_for_access allow "Entfernen der statischen Policy"

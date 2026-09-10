#!/usr/bin/env bash
set -Eeuo pipefail

readonly SCENARIO_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$SCENARIO_DIR/lib.sh"
require_e2e_environment

step "[E2E-04] Policy für die aktuelle UTC-Stunde"
utc_hour="$(date -u +%H)"
utc_hour="$((10#$utc_hour))"
install_policy "20-time-deny" <<EOF
policy "e2e current UTC hour deny"
deny
    action == "file_open";
    resource.path == "$TARGET_FILE";
    environment.utc.hour == $utc_hour;
EOF
wait_for_access deny "Zeit-Policy für aktuelle UTC-Stunde"
remove_policy_and_wait "20-time-deny"
wait_for_access allow "Entfernen der Zeit-Policy"

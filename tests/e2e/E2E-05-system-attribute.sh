#!/usr/bin/env bash
set -Eeuo pipefail

readonly SCENARIO_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$SCENARIO_DIR/lib.sh"
require_e2e_environment

step "[E2E-05] Ereignisgesteuertes Systemattribut system.defcon"
read -r policy_generation _ < <(read_generations)
install_policy "30-defcon-deny" <<EOF
policy "e2e defcon deny"
deny
    action == "file_open";
    resource.path == "$TARGET_FILE";
    system.defcon <= 2;
EOF
wait_for_generation_change policy "$policy_generation" "Aktivierung der DEFCON-Policy"
wait_for_access allow "DEFCON 5 soll die Policy nicht erfüllen"
set_defcon 2
wait_for_access deny "DEFCON 2 soll den Zugriff verweigern"
set_defcon 5
wait_for_access allow "DEFCON 5 soll den Zugriff wieder erlauben"
remove_policy_and_wait "30-defcon-deny"
wait_for_access allow "Entfernen der Systemattribut-Policy"

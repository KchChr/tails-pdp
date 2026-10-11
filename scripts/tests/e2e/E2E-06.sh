#!/usr/bin/env bash
# Test-ID: E2E-06
set -Eeuo pipefail

readonly SCENARIO_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$SCENARIO_DIR/lib.sh"
require_e2e_environment

step "[E2E-06] Frei benanntes Subject-Attribut"
subject_uid="$(id -u)"
read -r policy_generation attribute_generation < <(read_generations)
set_subject_position "$subject_uid" "engineer"
wait_for_generation_change attribute "$attribute_generation" "Aktivierung des Subject-Attributs"
install_policy "40-subject-position-deny" <<EOF
policy "e2e subject position deny"
deny
    action == "file_open";
    resource.path == "$TARGET_FILE";
    subject.position == "intern";
EOF
wait_for_generation_change policy "$policy_generation" "Aktivierung der Subject-Attribut-Policy"
wait_for_access allow "Subject-Position engineer soll die Policy nicht erfüllen"
set_subject_position "$subject_uid" "intern"
wait_for_access deny "Subject-Position intern soll den Zugriff verweigern"
set_subject_position "$subject_uid" "engineer"
wait_for_access allow "Subject-Position engineer soll den Zugriff wieder erlauben"
remove_policy_and_wait "40-subject-position-deny"
remove_attribute_and_wait "$ATTRIBUTE_DIR/subjects/${subject_uid}.attributes"
wait_for_access allow "Entfernen der Subject-Attribut-Policy"

#!/usr/bin/env bash
set -Eeuo pipefail

readonly SCENARIO_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$SCENARIO_DIR/lib.sh"
require_e2e_environment

step "[E2E-07] Frei benanntes Resource-Attribut"
read -r policy_generation attribute_generation < <(read_generations)
set_resource_classification "public"
wait_for_generation_change attribute "$attribute_generation" "Aktivierung des Resource-Attributs"
install_policy "50-resource-classification-deny" <<EOF
policy "e2e resource classification deny"
deny
    action == "file_open";
    resource.path == "$TARGET_FILE";
    resource.classification == "internal";
EOF
wait_for_generation_change policy "$policy_generation" "Aktivierung der Resource-Attribut-Policy"
wait_for_access allow "Resource-Klassifikation public soll die Policy nicht erfüllen"
set_resource_classification "internal"
wait_for_access deny "Resource-Klassifikation internal soll den Zugriff verweigern"
set_resource_classification "public"
wait_for_access allow "Resource-Klassifikation public soll den Zugriff wieder erlauben"
remove_policy_and_wait "50-resource-classification-deny"
remove_attribute_and_wait "$ATTRIBUTE_DIR/resources${TARGET_FILE}.attributes"
wait_for_access allow "Entfernen der Resource-Attribut-Policy"

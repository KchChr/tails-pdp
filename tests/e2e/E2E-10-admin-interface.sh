#!/usr/bin/env bash
set -Eeuo pipefail

readonly SCENARIO_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$SCENARIO_DIR/lib.sh"
require_e2e_environment

step "[E2E-10] Administrationsschnittstelle zeigt aktive Daten und bleibt nur lesend"
install_policy "80-admin-deny" <<EOF
policy "e2e admin output deny"
deny
    action == "file_open";
    resource.path == "$TARGET_FILE";
EOF
wait_for_access deny "aktive Policy vor Prüfung der Administrationsausgabe"

first_output="$TEST_ROOT/e2e-10-admin-first.txt"
second_output="$TEST_ROOT/e2e-10-admin-second.txt"
"$ADM_TOOL_BIN" \
    --policy-dir "$POLICY_DIR" \
    --attributes-dir "$ATTRIBUTE_DIR" \
    show-active >"$first_output"

grep -Fq "generation policy=" "$first_output" \
    || fail "Administrationsausgabe enthält keine Generationen."
grep -Fq "FILE_OPEN_STATIC_POLICIES:" "$first_output" \
    || fail "Administrationsausgabe enthält keine statischen Policies."
grep -Fq "enabled=1 entitlement=Deny" "$first_output" \
    || fail "Aktive Deny-Policy fehlt in der Administrationsausgabe."
grep -Fq "resource=\"$TARGET_FILE\"" "$first_output" \
    || fail "Die Testressource fehlt in der Administrationsausgabe."
grep -Fq "ATTRIBUTES:" "$first_output" \
    || fail "Administrationsausgabe enthält keinen Attributabschnitt."
grep -Fq "system.defcon = 5" "$first_output" \
    || fail "Das aktive Systemattribut fehlt in der Administrationsausgabe."

first_generation="$(grep -Fm1 "generation policy=" "$first_output")"
"$ADM_TOOL_BIN" \
    --policy-dir "$POLICY_DIR" \
    --attributes-dir "$ATTRIBUTE_DIR" \
    show-active >"$second_output"
second_generation="$(grep -Fm1 "generation policy=" "$second_output")"
[[ "$first_generation" == "$second_generation" ]] \
    || fail "Der Nur-Lese-Aufruf hat die aktive Generation verändert."
wait_for_access deny "Administrationsaufruf darf die Entscheidung nicht verändern"

remove_policy_and_wait "80-admin-deny"
wait_for_access allow "Entfernen der Administrations-Testpolicy"

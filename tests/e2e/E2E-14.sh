#!/usr/bin/env bash
# Test-ID: E2E-14
set -Eeuo pipefail
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/../evaluation/shell.sh"
evaluation_scenario E2E-14

attribute_and_wait system.attributes 'defcon = 2'
policy_and_wait test deny 'system.defcon <= 2;'
expect_access deny
admin > "$TEST_ROOT/admin.txt"
active="$(grep 'enabled=1' "$TEST_ROOT/admin.txt")"
[[ "$(grep -c 'enabled=1' "$TEST_ROOT/admin.txt")" == 1 ]] || fail "Nicht genau eine aktive Policy"
[[ "$active" == *'entitlement=Deny'* ]] || fail "Deny fehlt"
[[ "$active" == *"inode=$(stat -c %i "$TARGET_FILE")"* ]] || fail "Ressourcenidentität fehlt"
grep -Fq 'attribute_condition=' "$TEST_ROOT/admin.txt"
grep -Fq 'system.defcon = 2' "$TEST_ROOT/admin.txt"
printf '%s\n' 'Nachweis: eindeutige aktive Deny-Policy, Inode, Bedingung und Attributwert; kein individuelles Auditlog.' > "$TEST_ROOT/observation.txt"

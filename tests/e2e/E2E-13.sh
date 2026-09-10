#!/usr/bin/env bash
# Test-ID: E2E-13
set -Eeuo pipefail
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/../evaluation/shell.sh"
evaluation_scenario E2E-13

attribute_and_wait system.attributes 'defcon = 2'
policy_and_wait test deny 'system.defcon <= 2;'
expect_access deny
before="$(read_generations)"
offset="$(log_offset)"
printf 'defcon = 9\n' | install_attribute "$ATTRIBUTE_DIR/system.attributes"
wait_for_new_log "$offset" 'Ignoring invalid stream attributes'
[[ "$(read_generations)" == "$before" ]] || fail "Ungültige Attributgeneration aktiviert"
expect_access deny
attribute_and_wait system.attributes 'defcon = 5'
expect_access allow

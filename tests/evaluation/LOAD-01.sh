#!/usr/bin/env bash
# Test-ID: LOAD-01
set -Eeuo pipefail
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/shell.sh"
evaluation_scenario LOAD-01

# 16 entries per policy kind; overflow must retain the active generation.
expected_count=0
for kind in static stream; do
    condition=''
    [[ "$kind" != stream ]] || condition='system.defcon <= 2;'
    for ((i=0; i<16; i++)); do
        policy_and_wait "$kind-$i" permit "$condition"
    done
    expected_count=$((expected_count + 16))
    [[ "$(admin | grep -c 'enabled=1')" == "$expected_count" ]]
    before="$(read_generations)"
    offset="$(log_offset)"
    policy_text overflow permit "$condition" | install_policy overflow
    wait_for_new_log "$offset" 'previous generation remains active'
    [[ "$(read_generations)" == "$before" ]] || fail "Policyüberlauf aktiviert"
    remove_policy overflow
    sleep 0.2
done
# 1024 entries total, shared by two banks. Alternate full 512-entry banks.
for revision in 1 2 3; do
    values=''
    for ((i=0; i<512; i++)); do values+="field$i = $revision"$'\n'; done
    attribute_and_wait system.attributes "$values"
    [[ "$(admin | grep -c '^system.field')" == 512 ]]
done
before="$(read_generations)"
for ((i=0; i<513; i++)); do printf 'field%s = 4\n' "$i"; done | install_attribute "$ATTRIBUTE_DIR/system.attributes"
# Avoid diagnostic file opens during the known runtime-teardown interval.
sleep 3
after="$(read_generations)"
printf 'before=%s\nafter=%s\naccepted_per_bank=512\nattempted_new_bank=513\n' "$before" "$after" > "$TEST_ROOT/capacity-observation.txt"
[[ "$after" == "$before" ]] || fail "Attributüberlauf aktiviert"
runtime_alive || fail "Runtime nach Attributüberlauf beendet (bekannter Produktfehler)"

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
# Use one existing policy slot to prove the active attribute values still enforce
# Deny after the rejected change (field0=3), then Allow after recovery (field0=4).
policy_and_wait stream-0 deny 'system.field0 == 3;'
expect_access deny
before="$(read_generations)"
admin show-attributes > "$TEST_ROOT/attributes-before.txt"
offset="$(log_offset)"
for ((i=0; i<513; i++)); do printf 'field%s = 4\n' "$i"; done | install_attribute "$ATTRIBUTE_DIR/system.attributes"
wait_for_new_log "$offset" 'ATTRIBUTES capacity exceeded: retained=512 requested=513 capacity=1024'
wait_for_new_log "$offset" 'ATTRIBUTES update rejected'
after="$(read_generations)"
[[ "$after" == "$before" ]] || fail "Attributüberlauf aktiviert"
runtime_alive || fail "Runtime nach abgelehntem Attributupdate beendet"
admin show-attributes > "$TEST_ROOT/attributes-after-rejection.txt"
cmp "$TEST_ROOT/attributes-before.txt" "$TEST_ROOT/attributes-after-rejection.txt"
expect_access deny

# Correct the file without restarting. The watcher must still activate updates.
values=''
for ((i=0; i<512; i++)); do values+="field$i = 4"$'\n'; done
attribute_and_wait system.attributes "$values"
expect_access allow
recovered="$(read_generations)"
[[ "$recovered" != "$before" ]] || fail "Korrigiertes Update nicht aktiviert"
[[ "$(admin | grep -c '^system.field')" == 512 ]]
# A further Deny proves enforcement is still attached, not just default Allow
# after a dead runtime.
values=''
for ((i=0; i<512; i++)); do values+="field$i = 3"$'\n'; done
attribute_and_wait system.attributes "$values"
expect_access deny
runtime_alive || fail "Runtime nach Wiederherstellung beendet"
printf 'before=%s\nafter_rejection=%s\nrecovered=%s\naccepted_per_bank=512\nrejected_new_bank=513\nenforcement=deny-allow-deny\n' \
    "$before" "$after" "$recovered" > "$TEST_ROOT/capacity-observation.txt"

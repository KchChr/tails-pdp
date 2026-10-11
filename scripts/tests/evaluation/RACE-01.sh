#!/usr/bin/env bash
# Test-ID: RACE-01
set -Eeuo pipefail
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/shell.sh"
evaluation_scenario RACE-01

start_probe race
for ((i=0; i<EVAL_REPEATS; i++)); do
    policy_and_wait test deny '' tails-fd-probe
    remove_policy_and_wait test
done
touch "$probe_dir/stop"
wait_for_probe_files result 1
wait "$probe_pid"
result=("$probe_dir"/result-*.json)
cp "${result[0]}" "$TEST_ROOT/race-observation.json"
iterations="$(sed -E 's/.*"iterations": ([0-9]+).*/\1/' "${result[0]}")"
[[ "$iterations" =~ ^[0-9]+$ ]] && (( iterations > 100 )) || fail "Zu wenige FD-Wechsel"
grep -Fq '"wrong_safe_closes": 0' "${result[0]}" || fail "Falscher Entzug eines sicheren FDs"

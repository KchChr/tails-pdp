#!/usr/bin/env bash
# Test-ID: STAB-01
set -Eeuo pipefail
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/shell.sh"
evaluation_scenario STAB-01

started=$SECONDS
for ((cycle=0; cycle<EVAL_STAB_CYCLES; cycle++)); do
    policy_and_wait test deny
    expect_access deny
    before="$(read_generations)"
    offset="$(log_offset)"
    printf 'invalid %s\n' "$cycle" | install_policy test
    wait_for_new_log "$offset" 'previous generation remains active'
    [[ "$(read_generations)" == "$before" ]] || fail "Ungültige Policy aktiviert"
    expect_access deny
    remove_policy_and_wait test
    expect_access allow
    # Same attribute rollback sequence as E2E-13, in the current fixture.
    EVAL_CHILD=E2E-13 bash "$EVAL_HELPERS/../e2e/E2E-13.sh"
    remove_policy_and_wait test
done
printf 'cycles=%s\nduration_seconds=%s\n' "$EVAL_STAB_CYCLES" "$((SECONDS - started))" > "$TEST_ROOT/stability-observation.txt"

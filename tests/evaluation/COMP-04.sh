#!/usr/bin/env bash
# Test-ID: COMP-04
set -Eeuo pipefail
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/shell.sh"
evaluation_scenario COMP-04

attribute_and_wait system.attributes 'defcon = 2'
policy_and_wait static deny
policy_and_wait stream deny 'system.defcon <= 2;'
before="$(read_generations)"
for command in show show-policies show-attributes; do
    admin "$command" > "$TEST_ROOT/$command.txt"
    admin "$command" > "$TEST_ROOT/$command-second.txt"
    cmp "$TEST_ROOT/$command.txt" "$TEST_ROOT/$command-second.txt"
    [[ "$(read_generations)" == "$before" ]] || fail "Generationen verändert"
    output="$TEST_ROOT/$command.txt"
    if [[ "$command" != show-attributes ]]; then
        [[ "$(grep -c 'enabled=1' "$output")" == 2 ]]
        [[ "$(grep -c 'enabled=0' "$output")" == 30 ]]
        grep -Fq 'FILE_OPEN_STATIC_POLICIES:' "$output"
        grep -Fq 'FILE_OPEN_STREAM_POLICIES:' "$output"
    else
        ! grep -Fq 'FILE_OPEN_' "$output"
    fi
    if [[ "$command" != show-policies ]]; then
        grep -Fq 'ATTRIBUTES:' "$output"
        grep -Fq 'system.defcon = 2' "$output"
    else
        ! grep -Fq 'ATTRIBUTES:' "$output"
    fi
    expect_access deny
done

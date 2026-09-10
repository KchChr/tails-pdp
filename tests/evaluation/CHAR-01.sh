#!/usr/bin/env bash
# Test-ID: CHAR-01
set -Eeuo pipefail
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/shell.sh"
evaluation_scenario CHAR-01

start_probe char 2
policy_and_wait test deny '' tails-fd-probe
check_probe_results '[true, true, true, true]' 2
for file in "$probe_dir"/result-*.json; do
    grep -Fq '"mmap_readable": true' "$file" || fail "mmap-Beobachtung fehlt: $file"
done
printf '%s\n' 'dup-/fork-FDs entzogen; mmap in Eltern- und Kindprozess weiterhin lesbar.' > "$TEST_ROOT/observation.txt"

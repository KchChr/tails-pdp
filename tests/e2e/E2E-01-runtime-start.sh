#!/usr/bin/env bash
set -Eeuo pipefail

readonly SCENARIO_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$SCENARIO_DIR/lib.sh"
require_e2e_environment

step "[E2E-01] Runtime-Start, Kernel-Verifier, LSM-Attach und Maps"
wait_for_log "Waiting for Ctrl-C" "erfolgreichen Runtime-Start"

for map_name in \
    POLICY_GENERATION \
    FILE_OPEN_STATIC_POLICIES \
    FILE_OPEN_STREAM_POLICIES \
    CURRENT_TIME \
    ATTRIBUTE_GENERATION \
    ATTRIBUTES; do
    [[ -e "$BPF_PIN_DIRECTORY/$map_name" ]] \
        || fail "Erwartete gepinnte Map '$map_name' fehlt."
done

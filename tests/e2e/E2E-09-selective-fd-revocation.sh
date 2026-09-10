#!/usr/bin/env bash
set -Eeuo pipefail

readonly SCENARIO_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$SCENARIO_DIR/lib.sh"
require_e2e_environment

step "[E2E-09] Userspace-PEP entzieht ausschließlich den verletzenden FD"
cat >"$TEST_ROOT/fd-holder.py" <<'PYTHON'
import errno
import os
import pathlib
import sys
import time

target_path, safe_path, ready_path, result_path = sys.argv[1:]
target_fd = os.open(target_path, os.O_RDONLY)
safe_fd = os.open(safe_path, os.O_RDONLY)
pathlib.Path(ready_path).write_text("ready\n")

deadline = time.monotonic() + 20
while time.monotonic() < deadline:
    try:
        os.fstat(target_fd)
        target_closed = False
    except OSError as error:
        if error.errno != errno.EBADF:
            raise
        target_closed = True

    try:
        os.fstat(safe_fd)
        safe_open = True
    except OSError:
        safe_open = False

    if target_closed:
        pathlib.Path(result_path).write_text(
            f"target_closed={target_closed} safe_open={safe_open}\n"
        )
        sys.exit(0 if safe_open else 2)
    time.sleep(0.1)

pathlib.Path(result_path).write_text("timeout\n")
sys.exit(3)
PYTHON

ready_file="$TEST_ROOT/fd-holder.ready"
result_file="$TEST_ROOT/fd-holder.result"
helper_pid=""

cleanup_helper() {
    if [[ -n "$helper_pid" ]] && kill -0 "$helper_pid" 2>/dev/null; then
        kill "$helper_pid" 2>/dev/null || true
        wait "$helper_pid" 2>/dev/null || true
    fi
}
trap cleanup_helper EXIT

python3 "$TEST_ROOT/fd-holder.py" \
    "$TARGET_FILE" "$SAFE_FILE" "$ready_file" "$result_file" &
helper_pid=$!

deadline=$((SECONDS + E2E_TIMEOUT_SECONDS))
while [[ ! -f "$ready_file" ]]; do
    (( SECONDS < deadline )) || fail "FD-Hilfsprozess wurde nicht rechtzeitig bereit."
    kill -0 "$helper_pid" 2>/dev/null || fail "FD-Hilfsprozess wurde vorzeitig beendet."
    sleep 0.1
done

install_policy "70-userspace-pep-deny" <<EOF
policy "e2e userspace PEP deny"
deny
    action == "file_open";
    resource.path == "$TARGET_FILE";
EOF

deadline=$((SECONDS + E2E_TIMEOUT_SECONDS))
while [[ ! -f "$result_file" ]]; do
    (( SECONDS < deadline )) || fail "Userspace-PEP hat den Ziel-FD nicht rechtzeitig entzogen."
    kill -0 "$helper_pid" 2>/dev/null || fail "FD-Hilfsprozess wurde vorzeitig beendet."
    sleep 0.1
done
wait "$helper_pid"
helper_pid=""
grep -Fqx "target_closed=True safe_open=True" "$result_file" \
    || fail "Userspace-PEP hat nicht ausschließlich den Ziel-FD geschlossen."
remove_policy_and_wait "70-userspace-pep-deny"
wait_for_access allow "Entfernen der Userspace-PEP-Testpolicy"

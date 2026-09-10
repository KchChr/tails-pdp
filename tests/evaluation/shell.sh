#!/usr/bin/env bash
# Shared fixture access. Scenario steps and assertions belong in the ID scripts.
EVAL_HELPERS="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$EVAL_HELPERS/../e2e/lib.sh"
shopt -s nullglob

evaluation_scenario() {
    local id="$1"
    if [[ "${EVAL_CHILD:-}" != "$id" ]]; then
        exec python3 "$EVAL_HELPERS/run.py" "$id"
    fi
    step "[$id]"
    probe_pids=()
    trap cleanup_probes EXIT
}

cleanup_probes() {
    local pid
    for pid in "${probe_pids[@]}"; do
        kill -TERM -- "-$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    done
}

runtime_alive() {
    local state
    state="$(ps -o stat= -p "$RUNTIME_PID")" || return 1
    [[ -n "$state" && "$state" != *Z* ]]
}

admin() {
    "$ADM_TOOL_BIN" --policy-dir "$POLICY_DIR" --attributes-dir "$ATTRIBUTE_DIR" "${1:-show-active}"
}

policy_text() {
    local name="$1" effect="${2:-deny}" conditions="${3:-}" command="${4:-}"
    printf 'policy "%s"\n%s\n action == "file_open";\n resource.path == "%s";\n' "$name" "$effect" "$TARGET_FILE"
    if [[ -n "$command" ]]; then printf ' command == "%s";\n' "$command"; fi
    printf '%s\n' "$conditions"
}

policy_and_wait() {
    local name="${1:-test}" effect="${2:-deny}" conditions="${3:-}" command="${4:-}" previous
    read -r previous _ < <(read_generations)
    policy_text "$name" "$effect" "$conditions" "$command" | install_policy "$name"
    wait_for_generation_change policy "$previous" "Policy $name"
}

attribute_and_wait() {
    local relative="$1" content="$2" previous
    read -r _ previous < <(read_generations)
    printf '%s\n' "$content" | install_attribute "$ATTRIBUTE_DIR/$relative"
    wait_for_generation_change attribute "$previous" "Attribut $relative"
}

# Unlike a failed cat command, this syscall helper distinguishes EPERM from
# unrelated I/O errors. It also optionally sets real/effective UID for E2E-15.
expect_access() {
    local expected="$1" actual deadline=$((SECONDS + E2E_TIMEOUT_SECONDS))
    while (( SECONDS < deadline )); do
        runtime_alive || fail "Runtime beendet"
        actual="$(python3 "$EVAL_HELPERS/access.py" "$TARGET_FILE")" || return 1
        [[ "$actual" == "$expected" ]] && return 0
        sleep 0.01
    done
    fail "Zugriff nicht wie erwartet: $expected"
}

log_offset() { wc -l < "$RUNTIME_LOG"; }
wait_for_new_log() {
    local offset="$1" pattern="$2" deadline=$((SECONDS + E2E_TIMEOUT_SECONDS))
    while (( SECONDS < deadline )); do
        if tail -n "+$((offset + 1))" "$RUNTIME_LOG" | grep -Fq -- "$pattern"; then return 0; fi
        runtime_alive || fail "Runtime beendet"
        sleep 0.01
    done
    fail "Neue Logmeldung fehlt: $pattern"
}

start_probe() {
    local mode="$1" count="${2:-1}"
    probe_dir="$TEST_ROOT/probe-${#probe_pids[@]}"
    mkdir "$probe_dir"
    setsid python3 "$EVAL_HELPERS/fd_probe.py" "$mode" "$TARGET_FILE" "$SAFE_FILE" "$probe_dir" >"$probe_dir/stdout.log" 2>"$probe_dir/stderr.log" &
    probe_pid=$!
    probe_pids+=("$probe_pid")
    wait_for_probe_files ready "$count"
}

wait_for_probe_files() {
    local kind="$1" count="$2" deadline=$((SECONDS + E2E_TIMEOUT_SECONDS))
    local files
    while (( SECONDS < deadline )); do
        files=("$probe_dir/$kind-"*.json)
        [[ "${#files[@]}" -eq "$count" ]] && return 0
        kill -0 "$probe_pid" 2>/dev/null || fail "Hilfsprozess beendet, bevor $kind vorlag"
        sleep 0.01
    done
    fail "Timeout: Hilfsprozess $kind"
}

check_probe_results() {
    local expected_closed="$1" count="${2:-1}" file
    wait_for_probe_files result "$count"
    wait "$probe_pid"
    for file in "$probe_dir"/result-*.json; do
        grep -Fq "\"closed\": $expected_closed" "$file" || fail "Falsche entzogene FDs: $file"
        grep -Fq '"safe_open": [true, true]' "$file" || fail "Erlaubter FD entzogen: $file"
    done
}

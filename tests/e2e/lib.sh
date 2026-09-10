#!/usr/bin/env bash

# Gemeinsame Hilfsfunktionen der privilegierten E2E-Szenarien.

require_e2e_environment() {
    local variable
    for variable in \
        PROJECT_ROOT TEST_ROOT POLICY_DIR ATTRIBUTE_DIR RUNTIME_LOG \
        TARGET_FILE SAFE_FILE BPF_PIN_DIRECTORY RUNTIME_PID \
        TAILS_PDP_BIN ADM_TOOL_BIN E2E_TIMEOUT_SECONDS; do
        if [[ -z "${!variable:-}" ]]; then
            echo "Fehler: E2E-Variable '$variable' fehlt. Tests über test-e2e.sh starten." >&2
            exit 1
        fi
    done
}

step() {
    echo
    echo "==> $1"
}

fail() {
    echo "Fehler: $1" >&2
    return 1

}
wait_for_log() {
    local pattern="$1"
    local description="$2"
    local deadline=$((SECONDS + E2E_TIMEOUT_SECONDS))

    while (( SECONDS < deadline )); do
        if grep -Fq -- "$pattern" "$RUNTIME_LOG" 2>/dev/null; then
            return 0
        fi
        if ! kill -0 "$RUNTIME_PID" 2>/dev/null; then
            fail "tails-pdp wurde beendet, während auf '$description' gewartet wurde."
        fi
        sleep 0.2
    done

    fail "Timeout beim Warten auf '$description'."
}

can_read_target() {
    cat "$TARGET_FILE" >/dev/null 2>&1
}

wait_for_access() {
    local expected="$1"
    local description="$2"
    local deadline=$((SECONDS + E2E_TIMEOUT_SECONDS))

    while (( SECONDS < deadline )); do
        if can_read_target; then
            [[ "$expected" == "allow" ]] && return 0
        else
            [[ "$expected" == "deny" ]] && return 0
        fi
        sleep 0.2
    done

    fail "Erwarteter Zugriffszustand '$expected' wurde nicht erreicht: $description"
}

read_generations() {
    local output
    local generation_line
    output="$(
        "$ADM_TOOL_BIN" \
            --policy-dir "$POLICY_DIR" \
            --attributes-dir "$ATTRIBUTE_DIR" \
            show-active
    )" || return 1
    generation_line="$(grep -Fm1 "generation policy=" <<<"$output")" || return 1
    if [[ "$generation_line" =~ generation\ policy=([0-9]+).*attribute=([0-9]+) ]]; then
        printf '%s %s\n' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}"
        return 0
    fi
    return 1
}

wait_for_generation_change() {
    local kind="$1"
    local previous="$2"
    local description="$3"
    local deadline=$((SECONDS + E2E_TIMEOUT_SECONDS))
    local policy_generation
    local attribute_generation
    local current

    while (( SECONDS < deadline )); do
        if read -r policy_generation attribute_generation < <(read_generations); then
            if [[ "$kind" == "policy" ]]; then
                current="$policy_generation"
            else
                current="$attribute_generation"
            fi
            [[ "$current" != "$previous" ]] && return 0
        fi
        ! kill -0 "$RUNTIME_PID" 2>/dev/null \
            && fail "tails-pdp wurde während '$description' beendet."
        sleep 0.2
    done

    fail "Timeout beim Warten auf einen Generationswechsel: $description"
}

# Dateien werden mit einer vom Watcher ignorierten Endung geschrieben und erst
# anschließend atomar aktiviert. Dadurch sieht die Runtime keine Teildateien.
install_policy() {
    local name="$1"
    local temporary="$POLICY_DIR/$name.tmp"
    local destination="$POLICY_DIR/$name.policy"
    cat >"$temporary"
    mv -- "$temporary" "$destination"
}

remove_policy() {
    rm -f -- "$POLICY_DIR/$1.policy"
}

remove_policy_and_wait() {
    local name="$1"
    local policy_generation
    read -r policy_generation _ < <(read_generations)
    remove_policy "$name"
    wait_for_generation_change policy "$policy_generation" "Entfernen der Policy '$name'"
}

install_attribute() {
    local destination="$1"
    local temporary="${destination}.tmp"
    mkdir -p -- "$(dirname -- "$destination")"
    cat >"$temporary"
    mv -- "$temporary" "$destination"
}

remove_attribute_and_wait() {
    local path="$1"
    local attribute_generation
    read -r _ attribute_generation < <(read_generations)
    rm -f -- "$path"
    wait_for_generation_change attribute "$attribute_generation" "Entfernen von '$path'"
}

set_defcon() {
    local level="$1"
    install_attribute "$ATTRIBUTE_DIR/system.attributes" <<EOF
defcon = $level
EOF
}

set_subject_position() {
    local uid="$1"
    local position="$2"
    install_attribute "$ATTRIBUTE_DIR/subjects/${uid}.attributes" <<EOF
position = "$position"
EOF
}

set_resource_classification() {
    local classification="$1"
    install_attribute "$ATTRIBUTE_DIR/resources${TARGET_FILE}.attributes" <<EOF
classification = "$classification"
EOF
}

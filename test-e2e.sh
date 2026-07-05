#!/usr/bin/env bash

# Privilegierte End-to-End-Tests für tails-pdp.
#
# Dieses Skript startet den echten Userspace-Prozess, lädt das eBPF-Objekt durch den
# Kernel-Verifier, hängt den file_open-LSM-Hook an und prüft anschließend reale
# Zugriffsentscheidungen. Es verändert dabei vorübergehend den globalen BPF-Zustand unter
# /sys/fs/bpf/tails-pdp und darf deshalb nur auf einem dafür vorgesehenen Testsystem laufen.

set -Eeuo pipefail

readonly PROJECT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly TAILS_PDP_BIN="${TAILS_PDP_BIN:-$PROJECT_ROOT/target/release/tails-pdp}"
readonly ADM_TOOL_BIN="${ADM_TOOL_BIN:-$PROJECT_ROOT/target/release/tails-pdp-admintool}"
readonly E2E_TIMEOUT_SECONDS="${E2E_TIMEOUT_SECONDS:-15}"
readonly BPF_PIN_DIRECTORY="/sys/fs/bpf/tails-pdp"

# Der Test benötigt Root für BPF-LSM, gepinnte Maps und ptrace-basiertes FD-Enforcement.
# Beim erneuten Aufruf über sudo bleiben nur die explizit unterstützten Konfigurationsvariablen
# erhalten.
if [[ "${EUID}" -ne 0 ]]; then
    exec sudo --preserve-env=TAILS_PDP_BIN,ADM_TOOL_BIN,E2E_TIMEOUT_SECONDS "$0" "$@"
fi

if [[ "$(uname -s)" != "Linux" ]]; then
    echo "Fehler: test-e2e.sh benötigt Linux." >&2
    exit 1
fi

for command in bash cat date env grep mktemp mv pgrep python3 rm sleep tail; do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "Fehler: Benötigtes Kommando '$command' wurde nicht gefunden." >&2
        exit 1
    fi
done

if [[ ! -x "$TAILS_PDP_BIN" || ! -x "$ADM_TOOL_BIN" ]]; then
    echo "Fehler: Release-Binaries fehlen." >&2
    echo "Bitte zuerst ./test.sh ausführen." >&2
    exit 1
fi

if [[ ! -r /sys/kernel/btf/vmlinux ]]; then
    echo "Fehler: /sys/kernel/btf/vmlinux fehlt; eBPF-LSM kann nicht geladen werden." >&2
    exit 1
fi

if pgrep -x tails-pdp >/dev/null 2>&1; then
    echo "Fehler: Es läuft bereits ein tails-pdp-Prozess." >&2
    echo "Der E2E-Test beendet fremde Laufzeitprozesse bewusst nicht automatisch." >&2
    exit 1
fi

readonly TEST_ROOT="$(mktemp -d /tmp/tails-pdp-e2e.XXXXXX)"
readonly POLICY_DIR="$TEST_ROOT/policies"
readonly ATTRIBUTE_DIR="$TEST_ROOT/attributes"
readonly RUNTIME_LOG="$TEST_ROOT/tails-pdp.log"
readonly TARGET_FILE="$TEST_ROOT/protected.txt"
readonly SAFE_FILE="$TEST_ROOT/safe.txt"

runtime_pid=""
helper_pid=""

mkdir -p "$POLICY_DIR" "$ATTRIBUTE_DIR/subjects" "$ATTRIBUTE_DIR/resources"
printf 'geschuetzter Inhalt\n' >"$TARGET_FILE"
printf 'weiterhin erlaubter Inhalt\n' >"$SAFE_FILE"
printf 'defcon = 5\n' >"$ATTRIBUTE_DIR/system.attributes"

cleanup() {
    local status=$?
    trap - EXIT INT TERM

    # Hilfs- und Runtime-Prozess nur beenden, wenn sie von diesem Skript gestartet wurden.
    if [[ -n "$helper_pid" ]] && kill -0 "$helper_pid" 2>/dev/null; then
        kill "$helper_pid" 2>/dev/null || true
        wait "$helper_pid" 2>/dev/null || true
    fi
    if [[ -n "$runtime_pid" ]] && kill -0 "$runtime_pid" 2>/dev/null; then
        kill -INT "$runtime_pid" 2>/dev/null || true
        wait "$runtime_pid" 2>/dev/null || true
    fi

    # Gepinnte Test-Maps dürfen nach dem Test keine nachfolgenden Läufe beeinflussen.
    bash "$PROJECT_ROOT/remove_maps.sh" >/dev/null 2>&1 || true

    if [[ "$status" -eq 0 ]]; then
        rm -rf -- "$TEST_ROOT"
    else
        echo "E2E-Test fehlgeschlagen. Diagnoseartefakte bleiben erhalten unter:" >&2
        echo "  $TEST_ROOT" >&2
        if [[ -f "$RUNTIME_LOG" ]]; then
            echo "Letzte Runtime-Logzeilen:" >&2
            tail -n 40 "$RUNTIME_LOG" >&2 || true
        fi
    fi

    exit "$status"
}
# Signale werden in eindeutige Exit-Codes übersetzt. Der EXIT-Trap führt das Aufräumen dadurch
# genau einmal aus und behandelt einen Abbruch nicht versehentlich als erfolgreichen Test.
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

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
        if [[ -n "$runtime_pid" ]] && ! kill -0 "$runtime_pid" 2>/dev/null; then
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

# Policies werden zuerst unter einer ignorierten temporären Endung vollständig geschrieben und
# anschließend atomar auf .policy umbenannt. Der Watcher sieht dadurch keine halbfertige Datei.
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

set_defcon() {
    local level="$1"
    local temporary="$ATTRIBUTE_DIR/system.attributes.tmp"
    printf 'defcon = %s\n' "$level" >"$temporary"
    mv -- "$temporary" "$ATTRIBUTE_DIR/system.attributes"
}

step "Alte Test-Maps entfernen"
bash "$PROJECT_ROOT/remove_maps.sh" >/dev/null

step "Runtime starten und Verifier-/Attach-Erfolg prüfen"
(
    cd -- "$TEST_ROOT"
    exec env RUST_LOG=info TAILS_PDP_EBPF_DEBUG=1 "$TAILS_PDP_BIN"
) >"$RUNTIME_LOG" 2>&1 &
runtime_pid=$!

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

step "Leerer Policy-Stand erlaubt den Dateizugriff"
wait_for_access allow "Ausgangszustand ohne Policies"

step "Statische Deny-Policy wird geladen und durch den LSM-Hook erzwungen"
install_policy "10-static-deny" <<EOF
policy "e2e static deny"
deny
    action == "file_open";
    resource.path == "$TARGET_FILE";
EOF
wait_for_access deny "statische Deny-Policy"
"$ADM_TOOL_BIN" show-active >/dev/null
remove_policy "10-static-deny"
wait_for_access allow "Entfernen der statischen Policy"

step "UTC-Zeitbedingung verwendet CURRENT_TIME"
utc_hour="$(date -u +%H)"
utc_hour="$((10#$utc_hour))"
install_policy "20-time-deny" <<EOF
policy "e2e current UTC hour deny"
deny
    action == "file_open";
    resource.path == "$TARGET_FILE";
    environment.utc.hour == $utc_hour;
EOF
wait_for_access deny "Zeit-Policy für aktuelle UTC-Stunde"
remove_policy "20-time-deny"
wait_for_access allow "Entfernen der Zeit-Policy"

step "Ereignisgesteuertes Systemattribut verändert die Entscheidung"
install_policy "30-defcon-deny" <<EOF
policy "e2e defcon deny"
deny
    action == "file_open";
    resource.path == "$TARGET_FILE";
    system.defcon <= 2;
EOF
wait_for_access allow "DEFCON 5 soll die Policy nicht erfüllen"
set_defcon 2
wait_for_access deny "DEFCON 2 soll den Zugriff verweigern"
set_defcon 5
wait_for_access allow "DEFCON 5 soll den Zugriff wieder erlauben"
remove_policy "30-defcon-deny"

step "Ungültiges Update lässt die letzte gültige Generation aktiv"
install_policy "40-rollback" <<EOF
policy "e2e rollback deny"
deny
    action == "file_open";
    resource.path == "$TARGET_FILE";
EOF
wait_for_access deny "gültige Rollback-Ausgangspolicy"

# Fehlendes Semikolon macht das Update ungültig. Die zuvor aktive Deny-Generation muss aktiv
# bleiben und der Runtime-Prozess darf nicht beendet werden.
install_policy "40-rollback" <<EOF
policy "e2e rollback invalid"
deny
    action == "file_open"
    resource.path == "$TARGET_FILE";
EOF
wait_for_log "previous generation remains active" "Rollback nach ungültiger Policy"
wait_for_access deny "letzte gültige Generation nach Parserfehler"
remove_policy "40-rollback"
wait_for_access allow "Entfernen des ungültigen Policy-Stands"

step "Userspace-PEP schließt nur den tatsächlich verletzenden FD"
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
python3 "$TEST_ROOT/fd-holder.py" \
    "$TARGET_FILE" "$SAFE_FILE" "$ready_file" "$result_file" &
helper_pid=$!

deadline=$((SECONDS + E2E_TIMEOUT_SECONDS))
while [[ ! -f "$ready_file" ]]; do
    (( SECONDS < deadline )) || fail "FD-Hilfsprozess wurde nicht rechtzeitig bereit."
    kill -0 "$helper_pid" 2>/dev/null || fail "FD-Hilfsprozess wurde vorzeitig beendet."
    sleep 0.1
done

install_policy "50-userspace-pep-deny" <<EOF
policy "e2e userspace PEP deny"
deny
    action == "file_open";
    resource.path == "$TARGET_FILE";
EOF

deadline=$((SECONDS + E2E_TIMEOUT_SECONDS))
while [[ ! -f "$result_file" ]]; do
    (( SECONDS < deadline )) || fail "Userspace-PEP hat den Ziel-FD nicht rechtzeitig entzogen."
    sleep 0.1
done
wait "$helper_pid"
helper_pid=""
grep -Fqx "target_closed=True safe_open=True" "$result_file" \
    || fail "Userspace-PEP hat nicht ausschließlich den Ziel-FD geschlossen."
remove_policy "50-userspace-pep-deny"
wait_for_access allow "Entfernen der Userspace-PEP-Testpolicy"

step "Ergebnis"
echo "Alle privilegierten End-to-End-Tests waren erfolgreich."

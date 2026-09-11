#!/usr/bin/env bash

# Hauptdatei der privilegierten End-to-End-Tests für tails-pdp.
#
# Sie richtet eine gemeinsame Testumgebung ein, startet die echte Runtime und
# ruft anschließend für jede Test-ID genau ein Szenarioskript unter tests/e2e auf.
# Der Lauf verändert vorübergehend /sys/fs/bpf/tails-pdp und gehört deshalb auf
# ein dafür vorgesehenes Linux-Testsystem.

set -Eeuo pipefail

readonly PROJECT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
readonly E2E_SCENARIO_DIR="$PROJECT_ROOT/tests/e2e"
readonly TAILS_PDP_BIN="${TAILS_PDP_BIN:-$PROJECT_ROOT/target/release/tails-pdp}"
readonly ADM_TOOL_BIN="${ADM_TOOL_BIN:-$PROJECT_ROOT/target/release/tails-pdp-admintool}"
readonly E2E_TIMEOUT_SECONDS="${E2E_TIMEOUT_SECONDS:-15}"
readonly BPF_PIN_DIRECTORY="/sys/fs/bpf/tails-pdp"
readonly SCENARIOS=(
    E2E-01.sh
    E2E-02.sh
    E2E-03.sh
    E2E-04.sh
    E2E-05.sh
    E2E-06.sh
    E2E-07.sh
    E2E-08.sh
    E2E-09.sh
    E2E-10.sh
)

# Root wird für BPF-LSM, gepinnte Maps und ptrace-basiertes FD-Enforcement
# benötigt. Beim erneuten Aufruf bleiben nur unterstützte Variablen erhalten.
if [[ "${EUID}" -ne 0 ]]; then
    exec sudo --preserve-env=TAILS_PDP_BIN,ADM_TOOL_BIN,E2E_TIMEOUT_SECONDS "$0" "$@"
fi

if [[ "$(uname -s)" != "Linux" ]]; then
    echo "Fehler: tests/test-e2e.sh benötigt Linux." >&2
    exit 1
fi

for command in bash cat date dirname env grep id mkdir mktemp mv pgrep python3 rm sleep tail; do
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

for scenario in "${SCENARIOS[@]}"; do
    if [[ ! -r "$E2E_SCENARIO_DIR/$scenario" ]]; then
        echo "Fehler: E2E-Szenario '$scenario' fehlt oder ist nicht lesbar." >&2
        exit 1
    fi
done
if [[ ! -r "$E2E_SCENARIO_DIR/lib.sh" ]]; then
    echo "Fehler: Gemeinsame E2E-Hilfsdatei 'tests/e2e/lib.sh' fehlt." >&2
    exit 1
fi

readonly TEST_ROOT="$(mktemp -d /tmp/tails-pdp-e2e.XXXXXX)"
readonly POLICY_DIR="$TEST_ROOT/policies"
readonly ATTRIBUTE_DIR="$TEST_ROOT/attributes"
readonly RUNTIME_LOG="$TEST_ROOT/tails-pdp.log"
readonly TARGET_FILE="$TEST_ROOT/protected.txt"
readonly SAFE_FILE="$TEST_ROOT/safe.txt"

runtime_pid=""

mkdir -p "$POLICY_DIR" "$ATTRIBUTE_DIR/subjects" "$ATTRIBUTE_DIR/resources"
printf 'geschuetzter Inhalt\n' >"$TARGET_FILE"
printf 'weiterhin erlaubter Inhalt\n' >"$SAFE_FILE"
printf 'defcon = 5\n' >"$ATTRIBUTE_DIR/system.attributes"

cleanup() {
    local status=$?
    trap - EXIT INT TERM

    if [[ -n "$runtime_pid" ]] && kill -0 "$runtime_pid" 2>/dev/null; then
        kill -INT "$runtime_pid" 2>/dev/null || true
        wait "$runtime_pid" 2>/dev/null || true
    fi

    # Gepinnte Test-Maps dürfen nachfolgende Läufe nicht beeinflussen.
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
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

echo
echo "==> Gemeinsame E2E-Testumgebung vorbereiten"
bash "$PROJECT_ROOT/remove_maps.sh" >/dev/null

(
    cd -- "$TEST_ROOT"
    exec env RUST_LOG=info TAILS_PDP_EBPF_DEBUG=1 "$TAILS_PDP_BIN"
) >"$RUNTIME_LOG" 2>&1 &
runtime_pid=$!

export PROJECT_ROOT TEST_ROOT POLICY_DIR ATTRIBUTE_DIR RUNTIME_LOG TARGET_FILE SAFE_FILE
export BPF_PIN_DIRECTORY TAILS_PDP_BIN ADM_TOOL_BIN E2E_TIMEOUT_SECONDS
export RUNTIME_PID="$runtime_pid"

for scenario in "${SCENARIOS[@]}"; do
    bash "$E2E_SCENARIO_DIR/$scenario"
done

echo
echo "==> Ergebnis"
echo "Die bisherigen ${#SCENARIOS[@]} E2E-Szenarien waren erfolgreich."

# The new per-ID scripts use isolated runtimes. Release the shared fixture first.
kill -INT "$runtime_pid"
wait "$runtime_pid"
runtime_pid=""
bash "$PROJECT_ROOT/remove_maps.sh" >/dev/null
bash "$PROJECT_ROOT/tests/test-evaluation.sh" E2E-11 E2E-12 E2E-13 E2E-14 E2E-15 E2E-16 E2E-17

echo "Alle 17 privilegierten End-to-End-Tests waren erfolgreich."

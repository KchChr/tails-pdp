#!/usr/bin/env bash

# Zentrale, reproduzierbare Prüfkette für den gesamten Prototyp.
#
# Die Rust-Prüfungen laufen mit den Rechten des aufrufenden Benutzers. Für die anschließenden
# Kernel-, Attach-, Enforcement- und Evaluationsszenarien fordert das Skript über sudo gezielt
# Root-Rechte an. Diese Tests verändern vorübergehend die gepinnten Maps unter
# /sys/fs/bpf/tails-pdp und dürfen nur auf dem dedizierten Linux-Testsystem ausgeführt werden.

# -E: ERR-Trap würde in Funktionen weitergereicht, -e: beim ersten Fehler abbrechen,
# -u: nicht gesetzte Variablen als Fehler behandeln, pipefail: Pipeline-Fehler nicht verdecken.
set -Eeuo pipefail

# Unabhängig vom Aufrufverzeichnis immer aus dem Repository-Wurzelverzeichnis arbeiten.
readonly PROJECT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd -- "$PROJECT_ROOT"

# Aya und die Userspace-Komponenten verwenden Linux-spezifische APIs. Die vollständige Suite ist
# deshalb bewusst ein Zielsystem-Test und nicht nativ unter macOS ausführbar.
if [[ "$(uname -s)" != "Linux" ]]; then
    echo "Fehler: Die vollständige tails-pdp Testsuite benötigt Linux." >&2
    exit 1
fi

readonly -a WORKSPACE_PACKAGES=(
    tails-pdp
    tails-pdp-admintool
    tails-pdp-attribute-loader
    tails-pdp-common
    tails-pdp-policy-loader
    tails-pdp-userspace-common
    tails-pdp-userspace-pep
)

# E2E-11 bis E2E-17 werden bereits durch tests/test-e2e.sh ausgeführt. Hier stehen deshalb nur die
# übrigen privilegierten Evaluationsszenarien, damit kein Test doppelt läuft.
readonly -a EVALUATION_SCENARIOS=(
    COMP-04
    CHAR-01
    RACE-01
    PERF-01
    PERF-02
    PERF-03
    LOAD-01
    STAB-01
)

# Explizite --package-Argumente vermeiden, dass das no_std-eBPF-Crate als gewöhnlicher
# Userspace-Test gestartet wird. Das eBPF-Crate wird später über build.rs für das BPF-Target gebaut.
package_arguments=()
for package in "${WORKSPACE_PACKAGES[@]}"; do
    package_arguments+=(--package "$package")
done

run_step() {
    local description="$1"
    shift

    echo
    echo "==> $description"
    "$@"
}

run_privileged_step() {
    local description="$1"
    shift

    if [[ "${EUID}" -eq 0 ]]; then
        run_step "$description" "$@"
    else
        run_step "$description" \
            sudo --preserve-env=TAILS_PDP_BIN,ADM_TOOL_BIN,E2E_TIMEOUT_SECONDS,EVAL_TIMEOUT,EVAL_REPEATS,EVAL_STAB_CYCLES \
            "$@"
    fi
}

if [[ "${EUID}" -ne 0 ]] && ! command -v sudo >/dev/null 2>&1; then
    echo "Fehler: Für die privilegierten Systemtests wird sudo benötigt." >&2
    exit 1
fi

# Reine Formatprüfung: Es werden keine Dateien automatisch verändert.
run_step "Formatierung prüfen" \
    cargo fmt --all -- --check

# `.cargo/config.toml` konfiguriert global `sudo -E` als Runner. Unit-Tests benötigen keine
# Privilegien und sollen keine root-eigenen Build-Artefakte erzeugen, daher wird der Runner hier
# bewusst durch `env` ersetzt. --locked verhindert außerdem, dass ein Testlauf Cargo.lock oder die
# aufgelösten Dependency-Versionen verändert.
run_step "Alle automatisierten Unit- und Komponententests ausführen" \
    cargo test --locked "${package_arguments[@]}" --all-targets \
    --config 'target."cfg(all())".runner="env"'

# Clippy prüft Produktions-, Test- und Binärziele. Mit -D warnings wird jede Warnung zum Fehler.
run_step "Clippy ohne Warnungen ausführen" \
    cargo clippy --locked "${package_arguments[@]}" --all-targets -- -D warnings

# Der Build des Hauptprogramms führt über tails-pdp/build.rs auch den Release-Build des
# eBPF-Programms aus. Das prüft den BPF-Target-Build, aber nicht das Laden durch den Kernel-Verifier.
run_step "Release-Binaries einschließlich eBPF-Objekt bauen" \
    cargo build --locked --release --bin tails-pdp --bin tails-pdp-admintool

# Führt E2E-01 bis E2E-17 aus. E2E-11 bis E2E-17 verwenden dabei jeweils eine isolierte Runtime.
run_privileged_step "Alle privilegierten End-to-End-Tests ausführen" \
    bash "$PROJECT_ROOT/tests/test-e2e.sh"

# Ergänzt die E2E-Suite um reale Map-, Grenzfall-, Performance-, Last- und Stabilitätsprüfungen.
run_privileged_step "Ergänzende Evaluationsszenarien ausführen" \
    bash "$PROJECT_ROOT/tests/test-evaluation.sh" "${EVALUATION_SCENARIOS[@]}"

echo
echo "Alle automatisierten Tests, Qualitätsprüfungen und Evaluationsszenarien waren erfolgreich."

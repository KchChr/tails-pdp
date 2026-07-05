#!/usr/bin/env bash

# Nicht privilegierte, reproduzierbare Prüfkette für den gesamten Rust-Workspace.
#
# Dieses Skript verändert keine aktiven LSM-Hooks und keine gepinnten eBPF-Maps. Die echten
# Kernel-, Attach- und Enforcement-Szenarien stehen deshalb getrennt in test-e2e.sh.

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

echo
echo "Alle automatisierten Tests und Checks waren erfolgreich."
echo "Hinweis: Verifier-, Attach- und LSM-Enforcement-Tests benötigen weiterhin einen"
echo "privilegierten Lauf auf dem Zielsystem mit: sudo ./test-e2e.sh"

#!/usr/bin/env bash

set -Eeuo pipefail

readonly PROJECT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd -- "$PROJECT_ROOT"

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

run_step "Formatierung prüfen" \
    cargo fmt --all -- --check

# `.cargo/config.toml` konfiguriert global `sudo -E` als Runner. Unit-Tests benötigen keine
# Privilegien und sollen keine root-eigenen Build-Artefakte erzeugen, daher wird der Runner hier
# bewusst durch `env` ersetzt.
run_step "Alle automatisierten Unit- und Komponententests ausführen" \
    cargo test --locked "${package_arguments[@]}" --all-targets \
    --config 'target."cfg(all())".runner="env"'

run_step "Clippy ohne Warnungen ausführen" \
    cargo clippy --locked "${package_arguments[@]}" --all-targets -- -D warnings

# Der Build des Hauptprogramms führt über tails-pdp/build.rs auch den Release-Build des
# eBPF-Programms aus. Das prüft den BPF-Target-Build, aber nicht das Laden durch den Kernel-Verifier.
run_step "Release-Binaries einschließlich eBPF-Objekt bauen" \
    cargo build --locked --release --bin tails-pdp --bin tails-pdp-admintool

echo
echo "Alle automatisierten Tests und Checks waren erfolgreich."
echo "Hinweis: Verifier-, Attach- und LSM-Enforcement-Tests benötigen weiterhin einen"
echo "privilegierten manuellen Start mit: sudo -E ./target/release/tails-pdp"

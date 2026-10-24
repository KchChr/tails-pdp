#!/usr/bin/env bash
# Offline source build. Toolchains and system libraries must be supplied locally.
set -Eeuo pipefail

PROJECT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$PROJECT_ROOT"
export CARGO_NET_OFFLINE=true
export RUSTUP_TOOLCHAIN="$(<nix-config/rust-toolchain)"
ebpf_toolchain="$(<nix-config/ebpf-toolchain)"

for program in rustup cargo bpf-linker; do
    command -v "$program" >/dev/null || {
        printf 'Offline-Build: %s fehlt. Die mitgelieferte Buildumgebung ist unvollständig.\n' "$program" >&2
        exit 1
    }
done

# `rustup run` requires an installed toolchain and does not install one.
for toolchain in "$RUSTUP_TOOLCHAIN" "$ebpf_toolchain"; do
    if ! rustup run "$toolchain" rustc --version; then
        printf 'Offline-Build: Toolchain %s fehlt; es wird nichts heruntergeladen.\n' "$toolchain" >&2
        exit 1
    fi
done
sysroot="$(rustup run "$ebpf_toolchain" rustc --print sysroot)"
[[ -f "$sysroot/lib/rustlib/src/rust/library/core/Cargo.toml" ]] || {
    printf 'Offline-Build: rust-src für %s fehlt.\n' "$ebpf_toolchain" >&2
    exit 1
}
version="$(bpf-linker --version)"
[[ "$version" == 'bpf-linker 0.9.15' ]] || {
    printf 'Offline-Build: bpf-linker 0.9.15 benötigt, vorhanden: %s\n' "$version" >&2
    exit 1
}

# Inherited by aya-build and Cargo metadata; nested builds use vendor/ too.
cargo build --frozen --release --bin tails-pdp --bin tails-pdp-admintool

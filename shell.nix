{ pkgs ? import <nixpkgs> {} }:
let
  llvm = pkgs.llvmPackages_21;
in
pkgs.mkShell {
  buildInputs = [
    pkgs.git
    pkgs.pkg-config
    pkgs.libxml2
    pkgs.bpftools
    pkgs.pahole
    pkgs.elfutils
    pkgs.binutils
    llvm.llvm
    llvm.libllvm
    llvm.clang
    pkgs.zlib
    pkgs.rustup
    pkgs.cargo
    pkgs.cargo-generate
    pkgs.jq
  ];

  shellHook = ''
    # kein -u/-e, damit der Hook nicht still abbricht
    set -o pipefail

    export CARGO_HOME="$HOME/.cargo"
    export RUSTUP_HOME="$HOME/.rustup"
    export PATH="$CARGO_HOME/bin:$PATH"
    export NIX_ENFORCE_PURITY=0

    # LLVM fuer aya-rustc-llvm-proxy / bpf-linker
    export AYA_RUSTC_LLVM_PATH="${llvm.libllvm}/lib/libLLVM-21.so"
    export LD_LIBRARY_PATH="${pkgs.zlib.out}/lib:''${LD_LIBRARY_PATH:-}"

    # Nightly pinnen (Hook darf nie fehlschlagen)
    NIGHTLY="nightly-2025-08-01"
    if command -v rustup >/dev/null; then
      rustup toolchain install "$NIGHTLY" -c rust-src >/dev/null 2>&1 || true
      rustup target add bpfel-unknown-none --toolchain "$NIGHTLY" >/dev/null 2>&1 || true
      export RUSTUP_TOOLCHAIN="$NIGHTLY"
    fi

    # Wrapper-Binaries fuer die Dev-Shell.
    mkdir -p "$PWD/.nix-shell/bin"
    export PATH="$PWD/.nix-shell/bin:$PATH"

    cat > "$PWD/.nix-shell/bin/tails-pdp-admintool" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

candidates=(
  "$PWD/target/release/tails-pdp-admintool"
  "$PWD/target/x86_64-unknown-linux-musl/release/tails-pdp-admintool"
  "$PWD/target/aarch64-unknown-linux-musl/release/tails-pdp-admintool"
)

for candidate in "${candidates[@]}"; do
  if [ -x "$candidate" ]; then
    exec "$candidate" "$@"
  fi
done

echo "tails-pdp-admintool wurde noch nicht gebaut." >&2
echo "Erwartete Kandidaten:" >&2
printf '  %s\n' "${candidates[@]}" >&2
exit 1
EOF
    chmod +x "$PWD/.nix-shell/bin/tails-pdp-admintool"

    cat > "$PWD/.nix-shell/bin/tp-admin" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
exec "$PWD/.nix-shell/bin/tails-pdp-admintool" "$@"
EOF
    chmod +x "$PWD/.nix-shell/bin/tp-admin"

    # Manuell aufrufbarer Installer fuer Tools
    setup-bpf-tools() {
      WANT_BPF_LINKER="0.9.15"
      if ! command -v bpf-linker >/dev/null || ! bpf-linker -V 2>/dev/null | grep -q "bpf-linker $WANT_BPF_LINKER"; then
        echo "[setup] installing bpf-linker $WANT_BPF_LINKER (features=llvm-21)"
        cargo install --force bpf-linker --version "$WANT_BPF_LINKER" --no-default-features --features llvm-21 || return
      fi
      if ! command -v aya-tool >/dev/null; then
        echo "[setup] installing aya-tool (git)"
        cargo install --locked --git https://github.com/aya-rs/aya aya-tool || return
      fi
      echo "[setup] done."
    }

    echo
    echo "=== Nix dev shell ready ==="
    echo "IN_NIX_SHELL=''${IN_NIX_SHELL:-}  (leer? -> evtl. schon in nix-shell)"
    echo "AYA_RUSTC_LLVM_PATH=$AYA_RUSTC_LLVM_PATH"
    command -v clang >/dev/null && echo "clang: $(clang --version | head -n1)"
    command -v bpftool >/dev/null && echo "bpftool: $(bpftool -V | head -n1)"
    command -v rustup >/dev/null && rustup show active-toolchain || true
    echo "Admin tool: tails-pdp-admintool oder tp-admin"
    echo "Tipp: 'setup-bpf-tools' ausfuehren, um bpf-linker & aya-tool zu installieren."
    echo "========================================"
    echo
  '';
}

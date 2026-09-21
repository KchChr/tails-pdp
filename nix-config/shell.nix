{ pkgs ? import <nixpkgs> {} }:
let
  llvm = pkgs.llvmPackages_21;
in
pkgs.mkShell {
  buildInputs = [
    pkgs.bashInteractive
    pkgs.git
    pkgs.coreutils
    pkgs.gnugrep
    pkgs.procps
    pkgs.python3
    llvm.llvm
    llvm.libllvm
    pkgs.zlib
    pkgs.rustup
  ];

  shellHook = ''
    # kein -u/-e, damit der Hook nicht still abbricht
    set -o pipefail

    export CARGO_HOME="$HOME/.cargo"
    export RUSTUP_HOME="$HOME/.rustup"
    export PATH="$CARGO_HOME/bin:$PATH"
    export NIX_ENFORCE_PURITY=0

    # LLVM für aya-rustc-llvm-proxy / bpf-linker
    export AYA_RUSTC_LLVM_PATH="${llvm.libllvm}/lib/libLLVM-21.so"
    export LD_LIBRARY_PATH="${pkgs.zlib.out}/lib:''${LD_LIBRARY_PATH:-}"

    # Nightly und die für Build sowie Prüfkette benötigten Komponenten pinnen.
    #NIGHTLY="nightly-2025-08-01"
    NIGHTLY="stable"
    if command -v rustup >/dev/null; then
      rustup toolchain install "$NIGHTLY" \
        -c rust-src \
        -c rustfmt \
        -c clippy >/dev/null 2>&1 || true
      export RUSTUP_TOOLCHAIN="$NIGHTLY"
    fi

    # Manuell aufrufbarer Installer für den vom eBPF-Build benötigten Linker.
    setup-bpf-tools() {
      WANT_BPF_LINKER="0.9.15"
      if ! command -v bpf-linker >/dev/null || ! bpf-linker -V 2>/dev/null | grep -q "bpf-linker $WANT_BPF_LINKER"; then
        echo "[setup] installing bpf-linker $WANT_BPF_LINKER (features=llvm-21)"
        cargo install --force bpf-linker --version "$WANT_BPF_LINKER" --no-default-features --features llvm-21 || return
      fi
      echo "[setup] done."
    }


    tails-pdp-admintool() {
      sudo /home/hntr/tails-pdp/target/release/tails-pdp-admintool "$@"
    }


    echo
    echo "=== Nix dev shell ready ==="
    echo "IN_NIX_SHELL=''${IN_NIX_SHELL:-}  (leer? -> evtl. schon in nix-shell)"
    echo "AYA_RUSTC_LLVM_PATH=$AYA_RUSTC_LLVM_PATH"
    command -v rustup  >/dev/null && rustup show active-toolchain || true
    echo "Tipp: 'setup-bpf-tools' ausführen, um bpf-linker zu installieren."
    echo "========================================"
    echo
  '';
}

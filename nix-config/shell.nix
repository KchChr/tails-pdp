{ pkgs ? import <nixpkgs> {} }:
let
  llvm = pkgs.llvmPackages_21;
in
pkgs.mkShell {
  buildInputs = [
    pkgs.bashInteractive
    pkgs.bash-completion

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
    pkgs.cargo-generate  # <--- hier dazu
    pkgs.jq
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

    # Nightly pinnen (Hook darf nie fehlschlagen)
    NIGHTLY="nightly-2025-08-01"
    if command -v rustup >/dev/null; then
      rustup toolchain install "$NIGHTLY" -c rust-src >/dev/null 2>&1 || true
      rustup target add bpfel-unknown-none --toolchain "$NIGHTLY" >/dev/null 2>&1 || true
      export RUSTUP_TOOLCHAIN="$NIGHTLY"
    fi

    # Manuell aufrufbarer Installer für Tools
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


    tails-pdp-admintool() {
      sudo /home/hntr/tails-pdp/target/release/tails-pdp-admintool "$@"
    }


    echo
    echo "=== Nix dev shell ready ==="
    echo "IN_NIX_SHELL=''${IN_NIX_SHELL:-}  (leer? -> evtl. schon in nix-shell)"
    echo "AYA_RUSTC_LLVM_PATH=$AYA_RUSTC_LLVM_PATH"
    command -v clang >/dev/null && echo "clang: $(clang --version | head -n1)"
    command -v bpftool >/dev/null && echo "bpftool: $(bpftool -V | head -n1)"
    command -v rustup  >/dev/null && rustup show active-toolchain || true
    echo "Tipp: 'setup-bpf-tools' ausführen, um bpf-linker & aya-tool zu installieren."
    echo "========================================"
    echo
  '';
}

{ pkgs ? import <nixpkgs> {} }:
let
  llvm = pkgs.llvmPackages_21;
  projectRoot = builtins.toString ../.;
in
pkgs.mkShell {
  buildInputs = [
    pkgs.bashInteractive
    pkgs.git
    pkgs.coreutils
    pkgs.gnugrep
    pkgs.procps
    pkgs.python3
    pkgs.tmux
    llvm.llvm
    llvm.libllvm
    pkgs.zlib
    # LLVM benötigt libxml2 auch beim Linken von bpf-linker.
    pkgs.libxml2
    pkgs.rustup
  ];

  shellHook = ''
    # kein -u/-e, damit der Hook nicht still abbricht
    set -o pipefail

    export CARGO_HOME="$HOME/.cargo"
    export RUSTUP_HOME="$HOME/.rustup"
    export RUSTUP_AUTO_INSTALL=0
    export PATH="$CARGO_HOME/bin:$PATH"
    export NIX_ENFORCE_PURITY=0

    # LLVM für aya-rustc-llvm-proxy / bpf-linker
    export AYA_RUSTC_LLVM_PATH="${llvm.libllvm}/lib/libLLVM-21.so"
    export LD_LIBRARY_PATH="${pkgs.lib.makeLibraryPath [ pkgs.zlib pkgs.libxml2 ]}:''${LD_LIBRARY_PATH:-}"

    # Nur lokal vorhandene Toolchains verwenden; der Shell-Start lädt nichts nach.
    export RUSTUP_TOOLCHAIN="${pkgs.lib.strings.trim (builtins.readFile ./rust-toolchain)}"

    # Vorab bereitgestellten Linker prüfen, niemals während der Demo installieren.
    setup-bpf-tools() {
      WANT_BPF_LINKER="0.9.15"
      if ! command -v bpf-linker >/dev/null || ! bpf-linker -V 2>/dev/null | grep -q "bpf-linker $WANT_BPF_LINKER"; then
        echo "[setup] Offline-Abhängigkeit fehlt: bpf-linker $WANT_BPF_LINKER (LLVM 21)." >&2
        return 1
      fi
      echo "[setup] done."
    }


    tails-pdp-admintool() {
      (
        cd "${projectRoot}" || return
        sudo ./target/release/tails-pdp-admintool "$@"
      )
    }


    echo
    echo "=== Nix dev shell ready ==="
    echo "IN_NIX_SHELL=''${IN_NIX_SHELL:-}  (leer? -> evtl. schon in nix-shell)"
    echo "AYA_RUSTC_LLVM_PATH=$AYA_RUSTC_LLVM_PATH"
    echo "Offline-Build: Compiler, rust-src und bpf-linker müssen lokal bereitstehen."
    echo "========================================"
    echo
  '';
}

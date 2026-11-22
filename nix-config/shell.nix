{
  # The ISO supplies store paths via NIX_PATH; a normal VM uses pinned sources.
  sources ? let local = builtins.tryEval <tails-pdp-sources>;
    in if local.success then import local.value else import ../demo/sources.nix,
  pkgs ? import sources.nixpkgs { overlays = [ (import sources.rustOverlay) ]; }
}:
let
  toolPkgs = if pkgs ? rust-bin then pkgs else pkgs.extend (import sources.rustOverlay);
  tools = import ../demo/demo-toolchain.nix { pkgs = toolPkgs; };
  projectRoot = builtins.toString ../.;
in
toolPkgs.mkShell (tools.variables // {
  buildInputs = tools.packages;

  shellHook = ''
    # kein -u/-e, damit der Hook nicht still abbricht
    set -o pipefail

    export CARGO_HOME="$HOME/.cargo"
    export NIX_ENFORCE_PURITY=0
    # Compilers, rust-src and bpf-linker come from the shared Nix definition.
    # Keep Nix's binaries ahead of any old tools in ~/.cargo/bin.

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
    echo "Userspace: ${tools.stableName} | eBPF: ${tools.ebpfName} mit rust-src"
    echo "RUSTUP_HOME=$RUSTUP_HOME"
    echo "Compiler und bpf-linker werden durch Nix bereitgestellt."
    echo "========================================"
    echo
  '';
})

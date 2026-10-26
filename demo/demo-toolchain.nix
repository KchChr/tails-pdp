{ pkgs }:
let
  stableName = pkgs.lib.strings.trim (builtins.readFile ../nix-config/rust-toolchain);
  ebpfName = pkgs.lib.strings.trim (builtins.readFile ../nix-config/ebpf-toolchain);
  stable = pkgs.rust-bin.stable.${stableName}.default;
  ebpf = pkgs.rust-bin.nightly.${pkgs.lib.removePrefix "nightly-" ebpfName}.minimal.override {
    extensions = [ "rust-src" ];
  };
  llvm = pkgs.llvmPackages_21;
  # Do not inherit the default compiler's potentially different LLVM version.
  linker = pkgs.bpf-linker.overrideAttrs (old: {
    # buildRustPackage has already translated buildFeatures at this point.
    cargoBuildFeatures = [ "llvm-21" ];
    # Keep Cargo/rustc and the build/install hooks added by buildRustPackage.
    # Only replace the original LLVM dependency.
    nativeBuildInputs = builtins.filter (input: input != pkgs.rustc.llvm)
      (old.nativeBuildInputs or [ ]) ++ [ llvm.llvm ];
    nativeCheckInputs = [ ];
    doCheck = false;
  });
in
assert pkgs.lib.assertMsg (linker.version == "0.9.15") "Demo requires bpf-linker 0.9.15";
{
  inherit stableName ebpfName stable ebpf llvm linker;
  packages = with pkgs; [
    rustup linker llvm.llvm llvm.libllvm gcc gnumake pkg-config zlib libxml2
    bashInteractive coreutils findutils gnugrep gnused diffutils procps
    python3 tmux util-linux git iproute2 nano
  ];
  variables = {
    RUSTUP_TOOLCHAIN = stableName;
    RUSTUP_AUTO_INSTALL = "0";
    CARGO_NET_OFFLINE = "true";
    AYA_RUSTC_LLVM_PATH = "${llvm.libllvm}/lib/libLLVM-21.so";
    LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath [ pkgs.zlib pkgs.libxml2 ];
  };
}

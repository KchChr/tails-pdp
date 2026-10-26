# Run from the repository root: nix-build ./demo -A iso
let
  sources = import ./sources.nix;
  system = import (sources.nixpkgs + "/nixos/lib/eval-config.nix") {
    system = "x86_64-linux";
    specialArgs = { inherit sources; };
    modules = [ ./demo-iso.nix ];
  };
in
{
  iso = system.config.system.build.isoImage;
  # Useful for evaluation without building an ISO.
  configuration = system.config;
}

# Update these revisions deliberately, together with the toolchain checks.
{
  nixpkgs = builtins.fetchTarball {
    url = "https://github.com/NixOS/nixpkgs/archive/1f607aa79b6356ed45d3cd3c8079c196e79efa2c.tar.gz";
  };
  rustOverlay = builtins.fetchTarball {
    url = "https://github.com/oxalica/rust-overlay/archive/0d0575988e4bb9ebc4cf1afb1cec1ceac0b5914e.tar.gz";
  };
}

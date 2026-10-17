{ pkgs ? import <nixpkgs> {} }:
pkgs.mkShell {
  packages = with pkgs; [ bashInteractive coreutils gnugrep procps util-linux tmux python3 ];
}

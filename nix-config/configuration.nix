{ config, pkgs, lib, ... }:

{
  imports = [ ./hardware-configuration.nix ];

  # Der Standardkernel der verwendeten NixOS-Version wird genutzt.

  boot.loader.systemd-boot.enable = true;
  boot.loader.efi.canTouchEfiVariables = true;

  # NixOS erzeugt daraus den einzigen lsm=-Bootparameter.
  security.lsm = lib.mkForce [ "landlock" "yama" "bpf" ];

  # OverlayFS für Stage-1 sicherstellen (gegen "No such device")
  boot.initrd.kernelModules = [ "overlay" ];
  boot.kernelModules = [ "overlay" ];
  boot.initrd.supportedFilesystems = [ "overlay" ];
  boot.supportedFilesystems = [ "overlay" ];

  # Virtio-Module (falls benötigt, meist schon in hardware-configuration.nix vorhanden)
  # boot.initrd.availableKernelModules = [ "virtio_pci" "virtio_blk" "virtio_scsi" "sd_mod" "sr_mod" ];

  boot.loader.grub.enable = false;

  # Netzwerk/Hostname
  networking.hostName = "nixos";
  networking.networkmanager.enable = true;

  # Locale, Tastatur, Zeitzone (deutsch)
  i18n.defaultLocale = "de_DE.UTF-8";
  console.keyMap = "de";
  time.timeZone = "Europe/Berlin";
  programs.nix-ld.enable = true;

  # SSH
  services.openssh.enable = true;
  services.openssh.openFirewall = true;
  services.openssh.settings = {
    PermitRootLogin = "no";
    PasswordAuthentication = true;
  };

  # Benutzer
  users.users.root.initialPassword = "password";
  users.users.hntr = {
    isNormalUser = true;
    description = "Admin user";
    extraGroups = [ "wheel" "networkmanager" ];
    initialPassword = "password";
  };
  users.users.demo = {
    isNormalUser = true;
    description = "Demo user";
    extraGroups = [ "wheel" "networkmanager" ];
    initialPassword = "demo";
  };
  security.sudo.enable = true;
  # Demo und privilegierte Tests ohne Passwortabfrage auf der dedizierten VM.
  security.sudo.extraRules = [
    {
      users = [ "demo" ];
      commands = [
        { command = "ALL"; options = [ "NOPASSWD" ]; }
      ];
    }
  ];

  # Werkzeuge für den direkten Start von ./scripts/demo.sh ohne manuelle Nix-Shell.
  # Fehlende Release-Binaries baut das Demo-Skript in seiner Nix-Entwicklungsumgebung.
  environment.systemPackages = with pkgs; [
    bashInteractive coreutils gnugrep procps tmux

    # Build- und Administrationswerkzeuge
    rustc rustfmt clippy rust-analyzer rust-bindgen
    llvmPackages.clang llvmPackages.lld llvmPackages.llvm llvmPackages.libclang
    bc bison flex perl cpio gnumake gcc elfutils libelf ncurses
    util-linux wget file rsync xz zstd python3 gdb binutils nano pahole git parted
    (pkgs.writeShellScriptBin "kernel-rust-check" ''
      set -euo pipefail
      if [ ! -f Makefile ]; then
        echo 'Bitte im Linux-Kernel-Quellverzeichnis ausführen.' >&2
        exit 1
      fi
      if ! make LLVM=1 rustavailable; then
        echo 'RUST_IS_AVAILABLE=false — Toolchain prüfen.' >&2
        exit 1
      fi
      echo 'Toolchain OK: RUST_IS_AVAILABLE=true'
    '')
  ];

  # Systemweite Variablen für rust-src/libclang
  environment.variables = {
    RUST_LIB_SRC = builtins.toString pkgs.rust.packages.stable.rustPlatform.rustLibSrc;
    LIBCLANG_PATH = (builtins.toString pkgs.llvmPackages.libclang) + "/lib";
  };

  # QEMU Guest Agent
  services.qemuGuest.enable = true;

  system.stateVersion = "25.05";
}

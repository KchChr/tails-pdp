{ config, pkgs, lib, ... }:

let
  upstreamKernel =
    pkgs.callPackage
      ({ lib, fetchurl, buildLinux, ... }@args:
        buildLinux (args // rec {
          version = "6.16.12";
          modDirVersion = version;
          src = fetchurl {
            url = "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/snapshot/linux-6.16.12.tar.gz";
            hash = "sha256-LyPDCQEfnscTUfo4aWamm9l+Y2btkXAT1/VHHmRD9Us=";
          };
          withRust = true;
          ignoreConfigErrors = false;
          structuredExtraConfig = with lib.kernel; {
            SECURITY = yes;
            SECURITYFS = yes;
            RUST = yes;
            RUST_DEBUG_ASSERTIONS = no;
            RUST_OVERFLOW_CHECKS = yes;
            RUST_BUILD_ASSERT_ALLOW = no;
          };
        }))
      {};

  kernelPackages = pkgs.linuxPackagesFor upstreamKernel;
in {
  imports = [ ./hardware-configuration.nix ];

  boot.kernelPackages = kernelPackages;

  boot.loader.systemd-boot.enable = true;
  boot.loader.efi.canTouchEfiVariables = true;

  boot.kernelParams = [ "lsm=lockdown,capability,yama,apparmor,bpf" ];

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
  users.users.root.initialPassword = "173bcx";
  users.users.hntr = {
    isNormalUser = true;
    description = "Admin user";
    extraGroups = [ "wheel" "networkmanager" ];
    initialPassword = "password";
  };
  security.sudo.enable = true;

  # Build-Tools
  environment.systemPackages = with pkgs; [
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

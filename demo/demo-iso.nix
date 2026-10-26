{ pkgs, lib, modulesPath, sources, ... }:
let
  tools = import ./demo-toolchain.nix { inherit pkgs; };
  # An allowlist avoids including local results, keys, caches or build output.
  repository = lib.cleanSourceWith {
    src = ../.;
    filter = path: type:
      let
        relative = lib.removePrefix (toString ../. + "/") (toString path);
        top = builtins.head (lib.splitString "/" relative);
      in builtins.elem top [
        "Cargo.toml" "Cargo.lock" "README.md" ".cargo" "vendor" "scripts" "nix-config"
        "tails-pdp" "tails-pdp-admintool" "tails-pdp-attribute-loader"
        "tails-pdp-common" "tails-pdp-ebpf"
        "tails-pdp-userspace-common" "tails-pdp-policy-loader"
        "tails-pdp-userspace-pep" "policies" "attributes"
      ] && !(builtins.elem (baseNameOf path) [ "__pycache__" ".DS_Store" ]);
  };
in
{
  imports = [ "${modulesPath}/installer/cd-dvd/installation-cd-minimal.nix" ];
  nixpkgs.overlays = [ (import sources.rustOverlay) ];
  nixpkgs.config.allowUnfree = false;

  isoImage.isoName = "prototype-demo-x86_64-linux.iso";
  isoImage.volumeID = "PROTOTYPE_DEMO";
  isoImage.makeEfiBootable = true;
  isoImage.makeUsbBootable = true;
  security.lsm = lib.mkForce [ "landlock" "yama" "bpf" ];
  networking.hostName = "prototype-demo";
  networking.useDHCP = lib.mkDefault true;
  time.timeZone = "Europe/Berlin";
  i18n.defaultLocale = "de_DE.UTF-8";
  console.keyMap = "de";
  # The local console can be used to discover the DHCP address.
  services.getty.autologinUser = lib.mkForce "demo";
  services.getty.helpLine = lib.mkForce ''
    Prototyp-Demo: IP-Adresse mit ip -br address anzeigen.
    SSH: ssh -t demo@<IP-Adresse>   Passwort: demo
  '';
  services.qemuGuest.enable = true;

  services.openssh = {
    enable = true;
    openFirewall = true;
    settings = {
      PermitRootLogin = lib.mkForce "no";
      PasswordAuthentication = true;
      PermitEmptyPasswords = lib.mkForce false;
    };
  };
  # Override the installation media's passwordless installer accounts.
  users.users.root.initialHashedPassword = lib.mkForce "!";
  users.users.nixos.initialHashedPassword = lib.mkForce "!";
  users.users.demo = {
    isNormalUser = true;
    extraGroups = [ "wheel" ];
    initialPassword = "demo";
    shell = pkgs.bashInteractive;
  };
  security.sudo.extraRules = [ {
    users = [ "demo" ];
    commands = [ { command = "ALL"; options = [ "NOPASSWD" ]; } ];
  } ];

  environment.systemPackages = tools.packages;
  # Allow checking the customized linker before building the complete image.
  system.build.demoLinker = tools.linker;
  environment.variables = tools.variables;
  # Keep the exact Nixpkgs source available for manual offline test shells too.
  nix.nixPath = [ "nixpkgs=${sources.nixpkgs}" ];
  programs.bash.loginShellInit = builtins.readFile ./demo-login.sh;

  systemd.services.demo-workspace = {
    description = "Prepare writable offline prototype sources and Rust toolchains";
    wantedBy = [ "multi-user.target" ];
    before = [ "sshd.service" ];
    requiredBy = [ "sshd.service" ];
    serviceConfig = { Type = "oneshot"; RemainAfterExit = true; };
    path = [ pkgs.coreutils ];
    script = ''
      set -eu
      install -d -m 0755 /home/demo
      if [ ! -d /home/demo/tails-pdp ]; then
        cp -r ${repository} /home/demo/tails-pdp
        chmod -R u+w /home/demo/tails-pdp
      fi
      install -d /home/demo/.rustup/toolchains /home/demo/.cargo
      # rustup discovers these preinstalled toolchains without a download.
      ln -sfn ${tools.stable} /home/demo/.rustup/toolchains/${tools.stableName}-x86_64-unknown-linux-gnu
      ln -sfn ${tools.ebpf} /home/demo/.rustup/toolchains/${tools.ebpfName}-x86_64-unknown-linux-gnu
      chown -R demo:users /home/demo
    '';
  };
  system.stateVersion = "26.05";
}

# Offline-Demo als NixOS-Live-ISO

Diese Konfiguration baut ein x86_64-Live-ISO. Nach dem Booten startet ein
interaktiver SSH-Login als `demo` den Quellcode-Build und anschließend die
geführte tmux-Demo. Benutzername und Passwort sind `demo`; dieser Benutzer
hat auf dem dedizierten Demo-System sudo ohne Passwort.

## ISO erstellen

Auf einem x86_64-Linux-System mit Nix im Repository ausführen:

```bash
nix-build ./demo -A iso
ls -lh result/iso/
```

Der angepasste LLVM-21-Linker kann vorab separat gebaut und geprüft werden:

```bash
nix-build ./demo -A configuration.system.build.demoLinker -o result-demo-linker
./result-demo-linker/bin/bpf-linker --version
```

Die erwartete Ausgabe ist `bpf-linker 0.9.15`.

Der erste ISO-Build benötigt Internet für die in `sources.nix` auf feste
Commit-IDs gepinnten Nix-Quellen und die Paketquellen. Ein Linux-Remote-Builder
kann diesen Build auch von einem Mac aus übernehmen. Die Ausgabe liegt unter
`result/iso/prototype-demo-x86_64-linux.iso`.

`default.nix` ist der Build-Einstieg. `demo-iso.nix` beschreibt das Live-System,
`demo-toolchain.nix` die Werkzeuge und `demo-login.sh` den Login-Ablauf.
Ein Flake-Lockfile ist bei diesem klassischen Nix-Einstieg nicht erforderlich.
Die Rust-Versionen werden aus den vorhandenen Dateien unter `nix-config/`
gelesen: Stable für Userspace und die festgelegte Nightly-Version für eBPF.
LLVM 21 und bpf-linker 0.9.15 sind ebenfalls festgelegt.

## ISO verwenden

1. ISO in Proxmox einbinden, x86_64-VM mit 2 vCPUs und zunächst 8 GiB RAM
   starten. Für Quellen und Build-Ergebnisse wird das beschreibbare Live-System
   im RAM benutzt; eine Systeminstallation ist nicht notwendig.
2. In der VM-Konsole mit `ip -br address` die per DHCP erhaltene IP feststellen.
3. Vom eigenen Rechner verbinden:

   ```bash
   ssh -t demo@<IP-Adresse>
   ```

4. Der Build läuft mit Cargo im Offline-Modus. Danach startet tmux. Enter
   führt durch die Demo. Nach Ende oder Abbruch bleibt die SSH-Shell geöffnet.

Das ISO enthält die ausgewählten Repository-Quellen einschließlich `vendor/`
und die vollständigen Nix-Paketabhängigkeiten der eingebundenen Werkzeuge.
Beim Booten werden die Quellen in `/home/demo/tails-pdp` kopiert. Die gepinnten
Compiler und rust-src werden lokal für rustup registriert, ohne Installation
aus dem Netz. Ein erneuter Login führt einen inkrementellen Build aus.
Manuelle Tests können in der SSH-Shell mit `./scripts/test.sh` gestartet werden.

Änderungen, Build-Ergebnisse und Logs gehen beim Ausschalten verloren. Zum
Aufbewahren vor dem Ausschalten per SCP kopieren. Das Netzwerk muss für SSH
erreichbar bleiben; Internet ist nach Erstellung des ISO nicht erforderlich.

## Abnahme auf Linux

Diese Deklaration muss vor der Weitergabe auf Linux evaluiert, gebaut und als
frisches ISO gestartet werden. Auf einem Mac ohne Nix ist dieser Nachweis
nicht möglich. Insbesondere sind rustup-Erkennung der Nix-Toolchains,
Kernel/BTF, SSH-Login, RAM-Bedarf und der vollständige Demo-Ablauf zu prüfen.

Für den Offline-Nachweis Internet am Testnetz sperren, aber SSH zum Gast
erlauben. Nach frischem Boot ohne `target/` einloggen, den vollständigen Build
und die Demo durchführen und anschließend `./scripts/test.sh` ausführen.
Die vorherige VM-Konfiguration und deren `hardware-configuration.nix` werden
für dieses Live-ISO nicht verwendet.

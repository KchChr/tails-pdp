# Build, Start und Betrieb

## Abhängigkeiten

Das Projekt benötigt eine Linux-Zielumgebung mit eBPF- und LSM-Unterstützung. Für Entwicklung und
Build werden außerdem Rust-Tools benötigt. Die eBPF- und LSM-Anforderungen folgen aus dem
Kernel-Teil und dem BPF-LSM-Modell [[P10]](../tails-pdp-ebpf/src/hooks.rs), [[P12]](../tails-pdp-ebpf/src/maps.rs), [Q9], [Q10].

Wichtige Werkzeuge:

| Werkzeug | Zweck |
| --- | --- |
| Rust stable/nightly | Rust-Compiler und Cargo. |
| `rust-src` | nötig für eBPF-Builds mit `build-std`. |
| `bpf-linker` | Linker für eBPF-Binaries. |
| `bpftool` | Analyse von geladenen eBPF-Programmen und Maps. |
| `pahole` | häufig nötig für BTF-/Kernel-Typinformationen. |
| LLVM/Clang | Toolchain-Unterstützung für eBPF. |

Die Nix-Shell in `shell.nix` installiert viele dieser Werkzeuge und setzt unter anderem:

- `AYA_RUSTC_LLVM_PATH`
- `RUSTUP_TOOLCHAIN`
- Pfade zu Cargo/Rustup

## Build

Typischer Build auf dem Zielsystem:

```shell
cargo build --bin tails-pdp-admintool --release
cargo build --bin tails-pdp --release
```

Oder über das vorhandene Skript:

```shell
./run.sh
```

`run.sh` führt aktuell aus:

```shell
git pull
cargo build --bin tails-pdp-admintool --release
cargo run --bin tails-pdp --release
```

## Warum gibt es Build-Skripte?

`tails-pdp/build.rs` baut das eBPF-Crate `tails-pdp-ebpf` als Teil des Userspace-Builds und bindet
das Ergebnis später über `include_bytes_aligned!` in [`tails-pdp/src/main.rs`](../tails-pdp/src/main.rs) ein.

Wichtig ist dabei:

- eBPF-Code läuft ohne Standardbibliothek.
- eBPF-Code darf keine Panic-Unwinding-Strategie nutzen.
- `tails-pdp/build.rs` setzt deshalb `CARGO_PROFILE_RELEASE_PANIC=abort` und
  `CARGO_PROFILE_DEV_PANIC=abort`.

`tails-pdp-ebpf/build.rs` sorgt dafür, dass Cargo neu baut, wenn sich der gefundene `bpf-linker`
ändert.

## Start

Das Hauptprogramm muss mit Rechten laufen, die eBPF-Programme laden, Maps pinnen und LSM-Programme
anhängen dürfen. Praktisch bedeutet das meist `sudo`.

```shell
sudo -E ./target/release/tails-pdp
```

Für mehr Userspace-Logs:

```shell
RUST_LOG=debug sudo -E ./target/release/tails-pdp
```

Für eBPF-Debug-Ausgaben:

```shell
TAILS_PDP_EBPF_DEBUG=1 RUST_LOG=info sudo -E ./target/release/tails-pdp
```

## Was passiert beim Start?

[`tails-pdp/src/main.rs`](../tails-pdp/src/main.rs) führt vereinfacht folgende Schritte aus:

1. Logging initialisieren.
2. `RLIMIT_MEMLOCK` erhöhen.
3. Pin-Verzeichnis `/sys/fs/bpf/tails-pdp` erstellen.
4. Layout vorhandener gepinnter Maps prüfen.
5. eBPF-Objekt laden.
6. LSM-Programme mit BTF laden.
7. Debug-Logging-Map setzen.
8. Tail-Call-Maps befüllen.
9. Gepinnte Zeit- und Attribut-Maps über die Loader-Crates öffnen.
10. Policy-, Zeit- und Attributzustand initial synchronisieren.
11. Einstiegshook `file_open` anhängen.
12. Zeit-Updater, Attributloader, Policyloader, Userspace-PEP und Ctrl-C-Wait parallel ausführen.

## Rechte

Warum Root nötig ist:

- eBPF-Programme laden
- LSM-Hooks anhängen
- Maps unter `/sys/fs/bpf` pinnen oder öffnen
- `/proc/<pid>/fd` anderer Prozesse lesen
- per `ptrace` in fremden Prozessen FDs schließen

Das Admin-Tool braucht für reine Anzeige oft kein `sudo`, für schreibende Befehle aber schon.

## Typische Startfehler

### Inkompatibles Map-Layout

Beispiel:

```text
pinned map 'STREAM_POLICY' ... has an incompatible layout
```

Ursache: Eine gepinnte Map aus einer älteren Version hat andere Struct-Größen oder andere
`max_entries`.

Lösung:

```shell
sudo rm -f /sys/fs/bpf/tails-pdp/FILE_OPEN_STATIC_POLICIES
sudo rm -f /sys/fs/bpf/tails-pdp/FILE_OPEN_STREAM_POLICIES
sudo rm -f /sys/fs/bpf/tails-pdp/POLICY_GENERATION
sudo rm -f /sys/fs/bpf/tails-pdp/CURRENT_TIME
# Nur bei einer Aktualisierung von Versionen vor der Ein-Map-Umstellung nötig:
sudo rm -f /sys/fs/bpf/tails-pdp/CURRENT_TIME_ISO8601
sudo rm -f /sys/fs/bpf/tails-pdp/ATTRIBUTES
sudo rm -f /sys/fs/bpf/tails-pdp/ATTRIBUTE_GENERATION
```

### Verifier-Fehler

Beispiel:

```text
BPF program is too large
invalid access to map value
At program exit the register R0 has unknown scalar value
```

Ursache: Der eBPF-Code verletzt eine Verifier-Regel. Häufige Gründe sind zu große Programme, zu
viel Stack-Nutzung oder unsichere Pointer.

### `Operation not permitted`

Ursache kann sein:

- fehlende Root-Rechte
- Kernel verbietet unprivilegiertes eBPF
- LSM-eBPF nicht aktiviert
- Nix-Sandbox oder Shell-Policy blockiert `/dev/null`, `sudo` oder `/sys/fs/bpf`

### macOS-Build

Ein vollständiger `cargo check -p tails-pdp --bin tails-pdp` kann auf macOS scheitern, weil Aya
Linux-only-Syscalls aus `libc` benötigt. Cross-Compilation ist möglich, aber die echte Ausführung
und eBPF-Verifier-Prüfung muss auf Linux erfolgen [Q3], [Q7], [Q18], [Q20].

---

**Previous:** [Architektur und Datenfluss](02-architektur-und-datenfluss.md) | **Next:** [eBPF- und LSM-Teil](04-ebpf-und-lsm.md)

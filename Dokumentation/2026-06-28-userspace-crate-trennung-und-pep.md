# Userspace-Crate-Trennung und Userspace-PEP

Stand: 28. Juni 2026

## Ziel

Die bisher im Crate `tails-pdp` zusammengefassten Userspace-Komponenten wurden in eigene
Library-Crates ausgelagert. Sie laufen weiterhin gemeinsam im Prozess `tails-pdp`. Dadurch werden
die fachlichen Grenzen durch Cargo-Abhängigkeiten sichtbar, ohne den Lebenszyklus der eBPF-Programme
und LSM-Links auf mehrere Prozesse zu verteilen.

## Neue Crates

| Crate | Verantwortung |
| --- | --- |
| [`tails-pdp-policy-loader/`](../tails-pdp-policy-loader/) | Policy-Dateien lesen, parsen, validieren, in kernelgeeignete Einträge übersetzen und generationenbasiert aktivieren. |
| [`tails-pdp-attribute-loader/`](../tails-pdp-attribute-loader/) | System-, Subjekt-, Ressourcen- und Zeitattribute aktualisieren. |
| [`tails-pdp-userspace-pep/`](../tails-pdp-userspace-pep/) | Bestehende Dateizugriffe nachbewerten und unzulässige File Descriptors schließen. |
| [`tails-pdp-userspace-common/`](../tails-pdp-userspace-common/) | Gemeinsamer Pin-Pfad, Öffnen gepinnter Maps und rekursiver Verzeichnis-Watcher. |

Die Workspace-Mitglieder und Standardmitglieder sind in [`Cargo.toml`](../Cargo.toml) eingetragen.
Das Hauptprogramm bindet die neuen Crates in [`tails-pdp/Cargo.toml`](../tails-pdp/Cargo.toml) ein.

## Hauptprogramm

[`tails-pdp/src/main.rs`](../tails-pdp/src/main.rs) bleibt der einzige ausführbare Hauptprozess. Es
lädt das eBPF-Objekt, prüft Map-Layouts, richtet Tail Calls ein und erhält die LSM-Links am Leben.
Vor dem Anhängen des `file_open`-Hooks werden weiterhin Policies, Zeit und Attribute initial
geschrieben. Danach führt `tokio::select!` Policyloader, Attributloader, Zeit-Updater und
Userspace-PEP parallel aus.

Diese Reihenfolge verhindert ein Startfenster, in dem der Hook bereits aktiv wäre, aber noch keine
initialen Policy- und Attributzustände vorlägen. `run.sh` startet deshalb weiterhin nur das Binary
`tails-pdp`; es sind keine zusätzlichen Dienste oder Hintergrundprozesse erforderlich.

## Gepinnte Maps

[`tails-pdp-userspace-common/src/lib.rs`](../tails-pdp-userspace-common/src/lib.rs) stellt
`open_pinned_array` und `open_pinned_hash_map` bereit. Policyloader, Attributloader und
Userspace-PEP öffnen ihre Map-Handles damit einheitlich unter `/sys/fs/bpf/tails-pdp`.

Der Attributloader übernahm die Map-Handles zuvor direkt aus `aya::Ebpf`. Durch den Zugriff über die
Pins besitzt das Crate nun eine eigenständige Schnittstelle. Map-Namen, Schlüssel, Werte,
Maximalgrößen und Generationenmodell wurden nicht verändert; es liegt daher keine Änderung des
Kernel-/Userspace-Map-ABI vor.

## Policyloader

[`tails-pdp-policy-loader/src/policy_source.rs`](../tails-pdp-policy-loader/src/policy_source.rs)
enthält `PolicyDirectorySync`, Parser, Validierung und Generationenwechsel. Die interne Bezeichnung
für die Übersetzung wurde von `compile_*` auf `translate_*` geändert, damit deutlich wird, dass keine
Maschinencode-Kompilierung stattfindet.

[`tails-pdp-policy-loader/src/policy_loader.rs`](../tails-pdp-policy-loader/src/policy_loader.rs)
prüft die Layouts bereits gepinnter Maps. Nicht mehr verwendete direkte Ladefunktionen wurden
entfernt; die Policyquelle ist ausschließlich das überwachte Verzeichnis `policies/`.

## Attributloader

[`tails-pdp-attribute-loader/src/stream_attributes.rs`](../tails-pdp-attribute-loader/src/stream_attributes.rs)
verarbeitet `attributes/system.attributes`, Subjektattribute und Ressourcenattribute.
[`tails-pdp-attribute-loader/src/time.rs`](../tails-pdp-attribute-loader/src/time.rs) aktualisiert die
beiden Zeit-Maps. Beide Teile gehören zum selben Crate, weil sie die dynamische Entscheidungsgrundlage
für Stream-Policies bereitstellen.

## Userspace-PEP

Der bisherige Monitor heißt nun `tails-pdp-userspace-pep`. Der Einstieg ist
`run_userspace_pep` in [`tails-pdp-userspace-pep/src/pep.rs`](../tails-pdp-userspace-pep/src/pep.rs).
Das gezielte Schließen eines fremden File Descriptors bleibt in
[`tails-pdp-userspace-pep/src/fd_revoker.rs`](../tails-pdp-userspace-pep/src/fd_revoker.rs).

Die Bezeichnung wird wie folgt abgegrenzt:

- Der eBPF-LSM-Hook ist der Kernelspace-PEP für neue `file_open`-Operationen.
- Der Userspace-PEP kontrolliert bereits bestehende Dateizugriffe nach Policy- oder
  Attributänderungen erneut.
- Der Userspace-PEP setzt nicht nur Entscheidungen durch, sondern führt mangels eines separaten
  PDP-Prozesses auch die notwendige Nachbewertung anhand der gepinnten Maps lokal aus.

## Tests

Durchgeführt wurden:

- `cargo fmt --all -- --check`
- native Unit-Tests von `tails-pdp-common`: 10 Tests erfolgreich
- Testkompilierung der drei neuen fachlichen Crates für `x86_64-unknown-linux-musl`
- `cargo check-linux-x86_64`
- `cargo build-linux-x86_64`
- Thesis-Build mit `latexmk` in einem temporären Ausgabeverzeichnis
- Prüfung aller relativen Markdown-Links

Die Aya-abhängigen Crates können auf macOS nicht nativ ausgeführt werden, weil Aya Linux-spezifische
Systemaufrufe und Konstanten benötigt. Ihre Tests wurden deshalb lokal für das Linux-Ziel
kompiliert. Der ARM64-Check benötigt zusätzlich das lokal noch nicht installierte Rust-Ziel
`aarch64-unknown-linux-musl`.

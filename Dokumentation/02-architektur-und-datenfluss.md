# Architektur und Datenfluss

## Komponenten

Das Projekt ist ein Rust-Workspace mit vier Crates:

| Crate | Aufgabe |
| --- | --- |
| `tails-pdp` | Userspace-Hauptprogramm. Lädt eBPF, startet Loader, Monitor und Zeit-Updater. |
| `tails-pdp-common` | Gemeinsame Typen und Policy-Auswertung für Userspace und eBPF. |
| `tails-pdp-ebpf` | eBPF-Programme für LSM-Hooks. |
| `tails-pdp-admintool` | CLI zum Anzeigen und direkten Bearbeiten gepinnter Maps. |

Die Trennung ist wichtig, weil eBPF-Code andere Einschränkungen hat als normaler Userspace-Code.
Die Policy-Logik liegt deshalb so weit wie möglich in `tails-pdp-common`, damit Kernel und
Userspace dieselben Regeln verwenden [P8]. Das Laden von eBPF-Programmen und Maps erfolgt im
Userspace mit Aya [P1], [Q3], [Q18], [Q20].

## Ordnerstruktur

| Pfad | Bedeutung |
| --- | --- |
| [`tails-pdp/src/main.rs`](../tails-pdp/src/main.rs) | Startpunkt des Hauptprogramms. |
| [`tails-pdp/src/policy_source.rs`](../tails-pdp/src/policy_source.rs) | Liest Policy-Dateien und schreibt Maps. |
| [`tails-pdp/src/monitor.rs`](../tails-pdp/src/monitor.rs) | Überwacht laufende Prozesse und FDs. |
| [`tails-pdp/src/fd_revoker.rs`](../tails-pdp/src/fd_revoker.rs) | Schließt FDs in fremden Prozessen per `ptrace`. |
| [`tails-pdp/src/time.rs`](../tails-pdp/src/time.rs) | Aktualisiert Zeit-Maps. |
| [`tails-pdp/src/stream_attributes.rs`](../tails-pdp/src/stream_attributes.rs) | Aktualisiert strukturierte Attribute wie `system.defcon`. |
| [`tails-pdp/src/policy_loader.rs`](../tails-pdp/src/policy_loader.rs) | Prüft gepinnte Map-Layouts; enthält auch ältere Ladefunktionen. |
| [`tails-pdp-common/src/lib.rs`](../tails-pdp-common/src/lib.rs) | Structs, Enums, Konstanten und Auswertungsfunktionen. |
| [`tails-pdp-ebpf/src/hooks.rs`](../tails-pdp-ebpf/src/hooks.rs) | Einstieg in die LSM-Hooks. |
| [`tails-pdp-ebpf/src/helpers.rs`](../tails-pdp-ebpf/src/helpers.rs) | Liest Kernel-Daten wie Inode, Device, IP und Port. |
| [`tails-pdp-ebpf/src/maps.rs`](../tails-pdp-ebpf/src/maps.rs) | Definiert alle eBPF-Maps. |
| [`tails-pdp-ebpf/src/policies/`](../tails-pdp-ebpf/src/policies/) | Static-/Stream-Auswertung und Kombinieren. |
| [`tails-pdp-admintool/src/`](../tails-pdp-admintool/src/) | CLI-Parsing, Map-Zugriff und Ausgabe. |
| [`examples/`](../examples/) | Beispiel-Policies. |
| [`policies/`](../policies/) | Aktiver Policy-Ordner. |
| [`environment/`](../environment/) | Aktive Werte für strukturierte Attribute wie `system.defcon`, Subjekt- und Ressourcenattribute. |

## Grober Datenfluss

```text
Policy-Dateien in ./policies
        |
        v
Policy-Compiler im Userspace
        |
        | kompiliert Policies
        v
gepinnte eBPF-Maps unter /sys/fs/bpf/tails-pdp/
        |
        v
eBPF-LSM-Hook im Kernel
        |
        | liest aktuelle UID, Kommando, Datei oder Socket
        v
Policy-Auswertung in tails-pdp-common
        |
        v
Entscheidung: permit oder deny
```

Der Policy-Compiler in diesem Ablauf steht in
[`tails-pdp/src/policy_source.rs`](../tails-pdp/src/policy_source.rs).

## Datenfluss bei `file_open`

```text
Prozess ruft open() auf
        |
        v
LSM-Hook file_open
        |
        v
Hook-Einstieg
        |
        | Tail Call
        v
evaluate_file_open_static_policies
        |
        | Tail Call
        v
evaluate_file_open_stream_policies
        |
        | Tail Call
        v
combine_file_open
        |
        v
0 = erlauben, -1 = verweigern
```

Der Hook-Einstieg liegt in [`tails-pdp-ebpf/src/hooks.rs`](../tails-pdp-ebpf/src/hooks.rs) in der
Funktion `file_open`.

Die konkrete Auswertung liegt in:

- [`tails-pdp-ebpf/src/policies/file_open_static_policies.rs`](../tails-pdp-ebpf/src/policies/file_open_static_policies.rs)
- [`tails-pdp-ebpf/src/policies/file_open_stream_policies.rs`](../tails-pdp-ebpf/src/policies/file_open_stream_policies.rs)
- [`tails-pdp-ebpf/src/policies/combine.rs`](../tails-pdp-ebpf/src/policies/combine.rs)

Der Kernel-Teil liest die Ressource als `device + inode`, nicht als Pfad. Das ist robuster, weil im
LSM-Hook ein vollständiger Pfad schwer und verifier-unfreundlich zu ermitteln ist.

## Datenfluss bei `socket_bind`

```text
Prozess ruft bind() auf
        |
        v
LSM-Hook socket_bind
        |
        v
Hook-Einstieg
        |
        | Tail Call
        v
evaluate_socket_bind_static_policies
        |
        | Tail Call
        v
evaluate_socket_bind_stream_policies
        |
        | Tail Call
        v
combine_socket_bind
        |
        v
0 = erlauben, -1 = verweigern
```

Der Hook-Einstieg liegt in [`tails-pdp-ebpf/src/hooks.rs`](../tails-pdp-ebpf/src/hooks.rs) in der
Funktion `socket_bind`.

Der Hook liest lokale IP, Port, IP-Familie und Transportprotokoll. Das passiert in
[`tails-pdp-ebpf/src/helpers.rs`](../tails-pdp-ebpf/src/helpers.rs), besonders in `read_socket_bind_resource`.

## Warum Tail Calls?

Ein Tail Call ist ein Sprung von einem eBPF-Programm in ein anderes eBPF-Programm über eine
`ProgramArray`-Map. Dieses Projekt nutzt Tail Calls, um die Programme kleiner zu halten.

Das ist wichtig, weil der eBPF-Verifier große Programme oder komplizierte Kontrollflüsse ablehnen
kann. Statt alle Logik in einem Programm zu bündeln, wird die Auswertung aufgeteilt:

- Einstiegshook
- Static Policies
- Stream Policies
- Combine-Schritt

Die ProgramArray-Maps heißen:

- `FILE_OPEN_JUMP_TABLE`
- `SOCKET_BIND_JUMP_TABLE`

Sie werden im Userspace in [`tails-pdp/src/main.rs`](../tails-pdp/src/main.rs) befüllt.

## Static Policies und Stream Policies

Static Policies sind normale Regeln ohne Stream-Bedingung. Stream Policies enthalten eine Bedingung
gegen einen dynamischen Wert, aktuell Zeit oder strukturierte Attribute wie `system.defcon` [P3],
[P8], [P23].

Beispiel Static Policy:

```sapl
deny
    action == "file_open";
    subject.uid == 1000;
    command == "cat";
    resource.path == "/home/hntr/test.txt";
```

Beispiel Stream Policy:

```sapl
deny
    action == "socket_bind";
    resource.family == "inet";
    resource.ip == "0.0.0.0";
    resource.port == 8443;
    environment.utc.hour < 8;
```

Eine Stream Policy trifft nur eine Entscheidung, wenn ihre Stream-Bedingung wahr ist. Wenn die
Bedingung falsch ist, ist die Policy nicht anwendbar [P8].

Beispiel DEFCON-Policy über strukturierte Attribute:

```sapl
deny
    action == "file_open";
    subject.uid == 1000;
    resource.path == "/home/hntr/test.txt";
    system.defcon <= 2;
```

Der Wert dafür kommt aus [`environment/system.env`](../environment/system.env) und wird in
`ATTRIBUTES` geschrieben [P12], [P23], [P24].

---

**Previous:** [Projektüberblick und Grundbegriffe](01-ueberblick-und-grundbegriffe.md) | **Next:** [Build, Start und Betrieb](03-build-start-und-betrieb.md)

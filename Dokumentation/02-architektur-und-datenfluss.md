# Architektur und Datenfluss

## Komponenten

Das Projekt ist ein Rust-Workspace mit acht Crates:

| Crate | Aufgabe |
| --- | --- |
| `tails-pdp` | Hauptprogramm. Lädt eBPF und orchestriert die Userspace-Komponenten. |
| `tails-pdp-policy-loader` | Liest und validiert Policies und schreibt kernelgeeignete Map-Einträge. |
| `tails-pdp-attribute-loader` | Lädt strukturierte Attribute und aktualisiert die Zeit-Maps. |
| `tails-pdp-userspace-pep` | Prüft bestehende Dateizugriffe nachträglich und entzieht unzulässige File Descriptors. |
| `tails-pdp-userspace-common` | Gemeinsame Pin- und Dateisystem-Watcher-Infrastruktur für die Userspace-Crates. |
| `tails-pdp-common` | Gemeinsame Typen und Policy-Auswertung für Userspace und eBPF. |
| `tails-pdp-ebpf` | eBPF-Programme für LSM-Hooks. |
| `tails-pdp-admintool` | Read-only-CLI zum Anzeigen gepinnter Maps. |

Die Trennung ist wichtig, weil eBPF-Code andere Einschränkungen hat als normaler Userspace-Code.
Die Policy-Logik liegt deshalb so weit wie möglich in `tails-pdp-common`, damit Kernel und
Userspace dieselben Regeln verwenden [[P8]](../tails-pdp-common/src/lib.rs). Das Laden von eBPF-Programmen und Maps erfolgt im
Userspace mit Aya [[P1]](../tails-pdp/src/main.rs), [Q3], [Q18], [Q20].

## Ordnerstruktur

| Pfad | Bedeutung |
| --- | --- |
| [`tails-pdp/src/main.rs`](../tails-pdp/src/main.rs) | Startpunkt des Hauptprogramms. |
| [`tails-pdp-policy-loader/src/policy_source.rs`](../tails-pdp-policy-loader/src/policy_source.rs) | Liest Policy-Dateien und schreibt Maps. |
| [`tails-pdp-userspace-pep/src/pep.rs`](../tails-pdp-userspace-pep/src/pep.rs) | Überwacht laufende Prozesse und FDs. |
| [`tails-pdp-userspace-pep/src/fd_revoker.rs`](../tails-pdp-userspace-pep/src/fd_revoker.rs) | Schließt FDs in fremden Prozessen per `ptrace`. |
| [`tails-pdp-attribute-loader/src/time.rs`](../tails-pdp-attribute-loader/src/time.rs) | Aktualisiert Zeit-Maps. |
| [`tails-pdp-attribute-loader/src/stream_attributes.rs`](../tails-pdp-attribute-loader/src/stream_attributes.rs) | Aktualisiert strukturierte Attribute wie `system.defcon`. |
| [`tails-pdp-policy-loader/src/policy_loader.rs`](../tails-pdp-policy-loader/src/policy_loader.rs) | Prüft vor dem Laden die Layouts bereits gepinnter Maps. |
| [`tails-pdp-userspace-common/src/lib.rs`](../tails-pdp-userspace-common/src/lib.rs) | Definiert Pin-Pfad und gemeinsame Funktionen zum Öffnen gepinnter Maps. |
| [`tails-pdp-userspace-common/src/fs_watch.rs`](../tails-pdp-userspace-common/src/fs_watch.rs) | Rekursiver Linux-Verzeichnis-Watcher für Policy- und Attributänderungen. |
| [`tails-pdp-common/src/lib.rs`](../tails-pdp-common/src/lib.rs) | Structs, Enums, Konstanten und Auswertungsfunktionen. |
| [`tails-pdp-ebpf/src/hooks.rs`](../tails-pdp-ebpf/src/hooks.rs) | Einstieg in die LSM-Hooks. |
| [`tails-pdp-ebpf/src/helpers.rs`](../tails-pdp-ebpf/src/helpers.rs) | Liest Kernel-Daten wie Inode und Device. |
| [`tails-pdp-ebpf/src/maps.rs`](../tails-pdp-ebpf/src/maps.rs) | Definiert alle eBPF-Maps. |
| [`tails-pdp-ebpf/src/policies/`](../tails-pdp-ebpf/src/policies/) | Static-/Stream-Auswertung und Kombinieren. |
| [`tails-pdp-admintool/src/`](../tails-pdp-admintool/src/) | CLI-Parsing, Map-Zugriff und Ausgabe. |
| [`examples/`](../examples/) | Beispiel-Policies. |
| [`policies/`](../policies/) | Aktiver Policy-Ordner. |
| [`attributes/`](../attributes/) | Aktive Werte für strukturierte Attribute wie `system.defcon`, Subjekt- und Ressourcenattribute. |

## Grober Datenfluss

```text
Policy-Dateien in ./policies
        |
        v
Policyloader im Userspace
        |
        | übersetzt Policies in kernelgeeignete Einträge
        v
gepinnte eBPF-Maps unter /sys/fs/bpf/tails-pdp/
        |
        v
eBPF-LSM-Hook im Kernel
        |
        | liest aktuelle UID, Kommando und Dateiidentität
        v
Policy-Auswertung in tails-pdp-common
        |
        v
Entscheidung: permit oder deny
```

Der Policyloader in diesem Ablauf steht in
[`tails-pdp-policy-loader/src/policy_source.rs`](../tails-pdp-policy-loader/src/policy_source.rs).

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

## Ereignisbasierte Nachbewertung

Nach erfolgreicher Policy- oder Attributaktivierung sendet der jeweilige Loader einen internen
`EnforcementTrigger` an den Userspace-PEP. Der Trigger wird erst nach dem vollständigen Schreiben
der inaktiven Bank und dem Umschalten der Generation erzeugt. Ungültige Eingaben und fehlgeschlagene
Map-Updates behalten die vorherige Generation bei und lösen keine Neubewertung aus.

Der Kanal ist auf einen ausstehenden Trigger begrenzt. Dadurch bleiben Scans sequenziell; schnelle
Änderungen werden koalesziert und führen nach einem laufenden Scan zu höchstens einem weiteren Scan
mit den dann aktiven Generationen. Zeitabhängige Policies werden separat betrachtet: Der PEP
berechnet aus der aktiven Stream-Policy-Bank die nächste Zeitgrenze, an der sich eine Bedingung
ändern kann. Die sekündliche Aktualisierung von `CURRENT_TIME` für neue Kernelzugriffe bleibt
bestehen, löst aber selbst keinen vollständigen `/proc`-Scan aus.

Die Nachbewertung ist keine atomare Systemaufnahme und garantiert keinen sofortigen FD-Entzug.
Nach erfolgreicher Aktivierung einer entscheidungsrelevanten Policy-, Attribut- oder Zeitänderung
stößt der Prototyp ereignisgetrieben eine Neubewertung bestehender Dateizugriffe an. Bei einer
erkannten Verletzung versucht der Userspace-PEP, den zugeordneten File Descriptor zu schließen.

## Warum Tail Calls?

Ein Tail Call ist ein Sprung von einem eBPF-Programm in ein anderes eBPF-Programm über eine
`ProgramArray`-Map. Dieses Projekt nutzt Tail Calls, um die Programme kleiner zu halten.

Das ist wichtig, weil der eBPF-Verifier große Programme oder komplizierte Kontrollflüsse ablehnen
kann. Statt alle Logik in einem Programm zu bündeln, wird die Auswertung aufgeteilt:

- Einstiegshook
- Static Policies
- Stream Policies
- Combine-Schritt

Die ProgramArray-Map heißt `FILE_OPEN_JUMP_TABLE`.

Sie werden im Userspace in [`tails-pdp/src/main.rs`](../tails-pdp/src/main.rs) befüllt.

## Static Policies und Stream Policies

Static Policies sind normale Regeln ohne Stream-Bedingung. Stream Policies enthalten eine Bedingung
gegen einen dynamischen Wert, aktuell Zeit oder strukturierte Attribute wie `system.defcon` [[P3]](../tails-pdp-policy-loader/src/policy_source.rs),
[[P8]](../tails-pdp-common/src/lib.rs), [[P23]](../tails-pdp-attribute-loader/src/stream_attributes.rs).

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
    action == "file_open";
    resource.path == "/home/hntr/test.txt";
    environment.utc.hour < 8;
```

Eine Stream Policy trifft nur eine Entscheidung, wenn ihre Stream-Bedingung wahr ist. Wenn die
Bedingung falsch ist, ist die Policy nicht anwendbar [[P8]](../tails-pdp-common/src/lib.rs).

Beispiel DEFCON-Policy über strukturierte Attribute:

```sapl
deny
    action == "file_open";
    subject.uid == 1000;
    resource.path == "/home/hntr/test.txt";
    system.defcon <= 2;
```

Der Wert dafür kommt aus [`attributes/system.attributes`](../attributes/system.attributes) und wird in
`ATTRIBUTES` geschrieben [[P12]](../tails-pdp-ebpf/src/maps.rs), [[P23]](../tails-pdp-attribute-loader/src/stream_attributes.rs), [[P24]](../attributes/).

---

**Previous:** [Projektüberblick und Grundbegriffe](01-ueberblick-und-grundbegriffe.md) | **Next:** [Build, Start und Betrieb](03-build-start-und-betrieb.md)

# Userspace-Komponenten

## Hauptprogramm

Das Hauptprogramm steht in [`tails-pdp/src/main.rs`](../tails-pdp/src/main.rs).

Es ist verantwortlich für:

- eBPF-Objekt laden
- LSM-Programme laden und anhängen
- Tail-Call-Maps befüllen
- Layouts bereits gepinnter Maps prüfen
- initiale Policy- und Attributsynchronisation koordinieren
- Policyloader, Attributloader und Userspace-PEP parallel ausführen
- Logging konfigurieren

Der zentrale Loader ist `EbpfLoader::new()`. Das eBPF-Objekt wird mit
`aya::include_bytes_aligned!` eingebettet [[P1]](../tails-pdp/src/main.rs), [Q3], [Q20].

Die fachlichen Userspace-Komponenten sind als eigene Library-Crates umgesetzt, laufen aber
weiterhin gemeinsam im Prozess `tails-pdp`. Dadurch bleiben Startreihenfolge und Lebenszyklus der
LSM-Links zentral kontrolliert. Die gepinnten Maps bilden die gemeinsame Schnittstelle der Crates.

## Policy-Loader aus Dateien

Die Datei [`tails-pdp-policy-loader/src/policy_source.rs`](../tails-pdp-policy-loader/src/policy_source.rs) lädt Policies aus dem Ordner [`policies/`](../policies/).

Wichtige Typen:

| Typ | Bedeutung |
| --- | --- |
| `PolicyDirectorySync` | Verwaltet den laufenden Sync des Policy-Ordners. |
| `PolicyDocument` | Eine gelesene `.sapl`-Datei. |
| `ParsedPolicy` | Zwischendarstellung nach dem Parsen. |
| `TranslatedPolicies` | Fertige kernelgeeignete Policy-Structs für die Maps. |
| `PinnedPolicyMaps` | Geöffnete gepinnte Policy-Maps. |

## Policy-Sync-Ablauf

```text
./policies/*.sapl lesen
        |
        v
parse_policy_document
        |
        v
translate_policy
        |
        v
inactive Policy-Bank schreiben
        |
        v
POLICY_GENERATION erhöhen
```

Der wichtigste Sicherheitsaspekt ist die Generationenlogik.

Die Policy-Maps haben zwei Bänke:

- Bank 0
- Bank 1

`POLICY_GENERATION` entscheidet, welche Bank aktiv ist. Beim Update wird zuerst die inaktive Bank
vollständig beschrieben. Erst danach wird `POLICY_GENERATION` erhöht. Dadurch bleibt die alte
Generation aktiv, wenn das Schreiben der neuen Generation fehlschlägt.

Die Funktion dafür ist `PinnedPolicyMaps::commit`.

## Warum Update nur bei Änderung?

`PolicyDirectorySync` merkt sich:

- `last_applied_documents`
- `last_failed_documents`

Wenn sich die Dateien nicht geändert haben, wird nicht erneut geschrieben. Wenn ein fehlerhafter
Stand bereits fehlgeschlagen ist, wird er ebenfalls nicht jede Sekunde neu versucht. Das reduziert
unnötige Map-Schreibzugriffe.

## Zeit-Updater

[`tails-pdp-attribute-loader/src/time.rs`](../tails-pdp-attribute-loader/src/time.rs) aktualisiert die
Map `CURRENT_TIME` mit der Unix-Zeit in Sekunden. Kernel- und Userspace-PEP lesen denselben Wert.
Beide erzeugen daraus über
[`PolicyTime::from_unix_seconds`](../tails-pdp-common/src/lib.rs) die UTC-Komponenten Stunde,
Minute und Sekunde. Damit verwenden beide Ausführungspfade dieselbe Konvertierungslogik und
Stream Policies können weiterhin modulo- oder komponentenbasierte Zeitbedingungen auswerten.

Beispiel:

```sapl
environment.utc.hour < 8;
```

## Strukturierte Attribute

Zusätzlich überwacht [`tails-pdp-attribute-loader/src/stream_attributes.rs`](../tails-pdp-attribute-loader/src/stream_attributes.rs)
das Verzeichnis [`attributes/`](../attributes/). Globale Attribute stehen in `system.attributes`,
subjektbezogene Attribute in `subjects/<uid>.attributes` und dateibezogene Ressourcenattribute in
`resources/<pfad>.attributes`. Für Ressourcen wird der absolute Pfad ohne führenden `/` verwendet, zum
Beispiel `resources/home/hntr/test.txt.attributes` für `/home/hntr/test.txt`. Gültige Änderungen werden
in die gepinnte Map `ATTRIBUTES` geschrieben und über `ATTRIBUTE_GENERATION` atomar aktiviert. Bei
ungültigen Dateien bleibt die zuletzt gültige Attributgeneration aktiv.

Ressourcenattribute werden nicht über einen Pfad-Hash, sondern über die Dateiidentität aus Device
und Inode adressiert. Dadurch nutzt der Kernel beim `file_open` dieselbe Objektidentität wie der
Userspace beim Laden der Attributdateien.

DEFCON wird ebenfalls als strukturiertes Systemattribut geführt. Der Wert steht als `defcon = <wert>`
in `attributes/system.attributes`, wird als `system.defcon` in Policies verwendet und muss im Bereich
`1..=5` liegen.

Beispiel:

```ini
# attributes/system.attributes
defcon = 3

# attributes/subjects/1000.attributes
position = "engineer"

# attributes/resources/home/hntr/test.txt.attributes
classification = "internal"
clearanceLevel = 3
```

## Userspace-PEP

Der Userspace-PEP steht in [`tails-pdp-userspace-pep/src/pep.rs`](../tails-pdp-userspace-pep/src/pep.rs).

Der eBPF-LSM-Hook bildet den Kernelspace-PEP für neue Dateiöffnungen. Der zusätzliche
Userspace-PEP löst ein anderes Problem: Der LSM-Hook sieht nur den Moment, in dem etwas
passiert. Wenn eine Policy später aktiv wird, ist der Hook für bereits geöffnete Ressourcen schon
vorbei.

Der Userspace-PEP prüft deshalb regelmäßig laufende Prozesse:

- offene File Descriptors aus `/proc/<pid>/fd`
- Prozessinformationen aus `/proc/<pid>/status`

Danach verwendet er dieselben Funktionen aus `tails-pdp-common` wie der Kernel-Teil:

- `evaluate_file_open_static_policy`
- `evaluate_file_open_stream_policy`

Wenn eine Deny-Policy zutrifft, erzeugt der Userspace-PEP eine Violation und setzt die Entscheidung
durch Schließen des konkreten File Descriptors durch. Er enthält damit neben der Enforcement-Funktion
auch die für die Nachbewertung erforderliche Entscheidungslogik. Die `/proc`-Schnittstellen und
`ptrace` sind Linux-Interfaces und werden durch die Man-Pages beziehungsweise Kernel-Dokumentation
beschrieben [Q12], [Q13], [Q14], [Q15].

## FD-Revocation

[`tails-pdp-userspace-pep/src/fd_revoker.rs`](../tails-pdp-userspace-pep/src/fd_revoker.rs) versucht, einen File Descriptor in einem fremden Prozess zu schließen.

Das geschieht auf x86_64 Linux per `ptrace`:

1. Zielprozess attachen.
2. Register lesen.
3. Instruktion an aktueller RIP-Adresse kurz durch `syscall; int3` ersetzen.
4. Register für `close(fd)` vorbereiten.
5. Einen Schritt ausführen.
6. Originalcode und Register wiederherstellen.
7. Prozess detachen.

Das ist technisch mächtig, aber auch riskant. Es funktioniert aktuell nur auf `x86_64` Linux.

## Admin-Tool

Das Admin-Tool liegt in [`tails-pdp-admintool/src/`](../tails-pdp-admintool/src/).

Wichtige Dateien:

| Datei | Aufgabe |
| --- | --- |
| `cli.rs` | CLI-Definition mit Clap. |
| `maps.rs` | Öffnet gepinnte Maps. |
| `output.rs` | Formatiert Policies für `show` und `show-active`. |
| `lib.rs` | Führt Kommandos aus. |
| `main.rs` | Kleiner Einstieg, ruft `tails_pdp_admintool::run()`. |

Das Admin-Tool ist ein reines Inspektionswerkzeug. Es öffnet die gepinnten Maps lesend und zeigt
geladene Policies, Attribute und Generationen an. Änderungen erfolgen ausschließlich über die
Policy- und Attributdateien.

## Logging

Userspace-Logging nutzt `log` und `env_logger`.

Beispiele:

```shell
RUST_LOG=info sudo -E ./target/release/tails-pdp
RUST_LOG=debug sudo -E ./target/release/tails-pdp
```

Kernel-Debug-Logging über `bpf_printk!` ist standardmäßig aus und wird über die Map
`DEBUG_LOGGING` gesteuert. Das Hauptprogramm schreibt diese Map abhängig von
`TAILS_PDP_EBPF_DEBUG`.

---

**Previous:** [eBPF- und LSM-Teil](04-ebpf-und-lsm.md) | **Next:** [Policy-Logik und Datenstrukturen](06-policy-logik-und-datenstrukturen.md)

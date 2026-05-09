# Userspace-Komponenten

## Hauptprogramm

Das Hauptprogramm steht in `tails-pdp/src/main.rs`.

Es ist verantwortlich für:

- eBPF-Objekt laden
- LSM-Programme laden und anhängen
- Tail-Call-Maps befüllen
- gepinnte Maps prüfen und öffnen
- Policy-Verzeichnis überwachen
- Zeit-Maps aktualisieren
- Userspace-Monitor starten
- Logging konfigurieren

Der zentrale Loader ist `EbpfLoader::new()`. Das eBPF-Objekt wird mit
`aya::include_bytes_aligned!` eingebettet.

## Policy-Loader aus Dateien

Die Datei `tails-pdp/src/policy_source.rs` lädt Policies aus dem Ordner `policies/`.

Wichtige Typen:

| Typ | Bedeutung |
| --- | --- |
| `PolicyDirectorySync` | Verwaltet den laufenden Sync des Policy-Ordners. |
| `PolicyDocument` | Eine gelesene `.sapl`-Datei. |
| `ParsedPolicy` | Zwischendarstellung nach dem Parsen. |
| `CompiledPolicies` | Fertige Policy-Structs für die Maps. |
| `PinnedPolicyMaps` | Geöffnete gepinnte Policy-Maps. |

## Policy-Sync-Ablauf

```text
./policies/*.sapl lesen
        |
        v
parse_policy_document
        |
        v
compile_policy
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

`tails-pdp/src/time.rs` aktualisiert zwei Maps:

- `CURRENT_TIME`
- `CURRENT_TIME_ISO8601`

`CURRENT_TIME` enthält die Unix-Zeit in Sekunden. `CURRENT_TIME_ISO8601` enthält einzelne Felder:

- Jahr
- Monat
- Tag
- Stunde
- Minute
- Sekunde

Stream Policies können dadurch entweder modulo-basiert oder komponentenbasiert arbeiten.

Beispiel:

```sapl
environment.utc.hour < 8;
```

## Monitor

Der Monitor steht in `tails-pdp/src/monitor.rs`.

Er löst ein anderes Problem als der LSM-Hook. Der LSM-Hook sieht nur den Moment, in dem etwas
passiert. Wenn eine Policy später aktiv wird, ist der Hook für bereits geöffnete Ressourcen schon
vorbei.

Der Monitor prüft deshalb regelmäßig laufende Prozesse:

- aktive Sockets aus `/proc/net/tcp`, `/proc/net/tcp6`, `/proc/net/udp`, `/proc/net/udp6`
- offene File Descriptors aus `/proc/<pid>/fd`
- Prozessinformationen aus `/proc/<pid>/status`

Danach verwendet er dieselben Funktionen aus `tails-pdp-common` wie der Kernel-Teil:

- `evaluate_file_open_static_policy`
- `evaluate_file_open_stream_policy`
- `evaluate_socket_bind_static_policy`
- `evaluate_socket_bind_stream_policy`

Wenn eine Deny-Policy zutrifft, erzeugt der Monitor eine Violation.

## FD-Revocation

`tails-pdp/src/fd_revoker.rs` versucht, einen File Descriptor in einem fremden Prozess zu schließen.

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

Das Admin-Tool liegt in `tails-pdp-admintool/src/`.

Wichtige Dateien:

| Datei | Aufgabe |
| --- | --- |
| `cli.rs` | CLI-Definition mit Clap. |
| `maps.rs` | Öffnet gepinnte Maps. |
| `output.rs` | Formatiert Policies für `show` und `show-active`. |
| `lib.rs` | Führt Kommandos aus. |
| `main.rs` | Kleiner Einstieg, ruft `tails_pdp_admintool::run()`. |

Heute ist das Admin-Tool primär ein Inspektionswerkzeug. Es kann Maps zwar direkt verändern, aber
der Policy-Ordner `policies/` ist die eigentliche Quelle der Wahrheit. Direkte Map-Änderungen werden
beim nächsten erfolgreichen Policy-Sync überschrieben.

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


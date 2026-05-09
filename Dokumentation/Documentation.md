# tails-pdp Dokumentation

Diese Dokumentation beschreibt das Projekt `tails-pdp`. Sie richtet sich an Informatiker mit
Grundlagenwissen, aber ohne tiefere Erfahrung mit Rust, eBPF, Aya oder Linux Security Modules.

`tails-pdp` ist ein experimentelles Policy Decision Point System für Linux. Es lädt eBPF-Programme
in den Kernel, hängt sie an Linux-Security-Module-Hooks an und entscheidet dort, ob bestimmte
Aktionen erlaubt oder verboten werden. Zusätzlich gibt es Userspace-Komponenten, die Policies aus
Textdateien laden, eBPF-Maps befüllen, laufende Prozesse beobachten und Debug-Informationen
anzeigen.

## Lesereihenfolge

1. [Projektüberblick und Grundbegriffe](01-ueberblick-und-grundbegriffe.md)
2. [Architektur und Datenfluss](02-architektur-und-datenfluss.md)
3. [Build, Start und Betrieb](03-build-start-und-betrieb.md)
4. [eBPF- und LSM-Teil](04-ebpf-und-lsm.md)
5. [Userspace-Loader, Monitor und Admin-Tool](05-userspace-komponenten.md)
6. [Policy-Logik und Datenstrukturen](06-policy-logik-und-datenstrukturen.md)
7. [Fehlerbehandlung und Sicherheit](07-fehlerbehandlung-und-sicherheit.md)
8. [Debugging und Analyse](08-debugging-und-analyse.md)
9. [Tests und Teststrategie](09-tests.md)
10. [Offene Punkte und Einschränkungen](10-offene-punkte.md)
11. [Glossar](11-glossar.md)

## Wichtigste Dateien

| Pfad | Aufgabe |
| --- | --- |
| `tails-pdp/src/main.rs` | Lädt eBPF, richtet Maps und Tail Calls ein, startet Policy-Sync, Zeit-Update und Monitor. |
| `tails-pdp/src/policy_source.rs` | Liest `.sapl`-Policies aus `policies/`, kompiliert sie und schreibt sie in Maps. |
| `tails-pdp/src/monitor.rs` | Überwacht laufende Prozesse, FDs und Sockets im Userspace. |
| `tails-pdp/src/fd_revoker.rs` | Schließt fremde File Descriptors per `ptrace` auf x86_64 Linux. |
| `tails-pdp-common/src/lib.rs` | Gemeinsame Policy-Datenstrukturen und Auswertungslogik für Kernel und Userspace. |
| `tails-pdp-ebpf/src/hooks.rs` | Einstiegspunkte der eBPF-LSM-Hooks `file_open` und `socket_bind`. |
| `tails-pdp-ebpf/src/maps.rs` | Definition der eBPF-Maps. |
| `tails-pdp-ebpf/src/policies/` | eBPF-Policy-Auswertung und Kombinieren der Entscheidungen. |
| `tails-pdp-admintool/src/` | CLI zum Anzeigen und direkten Bearbeiten gepinnter Maps. |
| `examples/` | Beispiel-Policies, die nicht automatisch geladen werden. |
| `policies/` | Aktiver Policy-Ordner, den der Loader überwacht. |

## Kurzzusammenfassung

Der Kernel-Teil entscheidet bei den Hooks `file_open` und `socket_bind`, ob eine Aktion verboten
werden soll. Die Policies liegen in eBPF-Maps. Diese Maps werden durch den Userspace-Loader aus
SAPL-inspirierten Textdateien befüllt. Der Monitor prüft zusätzlich nachträglich laufende Prozesse,
weil eine Policy auch erst aktiv werden kann, nachdem ein Prozess bereits einen Socket oder eine
Datei geöffnet hat.


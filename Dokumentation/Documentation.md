# tails-pdp Dokumentation

Diese Dokumentation beschreibt das Projekt `tails-pdp`. 

`tails-pdp` ist ein experimentelles Policy Decision Point System für Linux. Es lädt eBPF-Programme
in den Kernel, hängt sie an Linux-Security-Module-Hooks an und entscheidet dort, ob bestimmte
Aktionen erlaubt oder verboten werden. Zusätzlich gibt es Userspace-Komponenten, die Policies aus
Textdateien laden, eBPF-Maps befüllen, Stream-Attribute wie DEFCON aktualisieren, laufende Prozesse
beobachten und Debug-Informationen anzeigen [P1], [P3], [P6], [P10], [P12], [P23]. Die allgemeinen
Grundlagen zu eBPF, BPF-Maps und BPF-LSM stammen aus der Linux-Kernel-Dokumentation [Q4], [Q5],
[Q9].

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
12. [Quellen und Zitierweise](12-quellen.md)

## Zitierweise

Die Dokumentation unterscheidet zwischen Projektquellen und externen Quellen:

- Projektquellen haben IDs wie `[P1]` und verweisen auf konkrete Dateien in diesem Repository.
- Externe Quellen haben IDs wie `[Q1]` und verweisen auf offizielle Dokumentation oder technische
  Referenzen.

Die vollständige Quellenliste steht in [Quellen und Zitierweise](12-quellen.md). Quellenhinweise
stehen direkt im Text, damit die Herkunft der jeweiligen Aussage beim Lesen sichtbar ist.

## Wichtigste Dateien

| Pfad | Aufgabe |
| --- | --- |
| [`tails-pdp/src/main.rs`](../tails-pdp/src/main.rs) | Lädt eBPF, richtet Maps und Tail Calls ein, startet Policy-Sync, Zeit-Update und Monitor. |
| [`tails-pdp/src/policy_source.rs`](../tails-pdp/src/policy_source.rs) | Liest `.sapl`-Policies aus [`policies/`](../policies/), kompiliert sie und schreibt sie in Maps. |
| [`tails-pdp/src/stream_attributes.rs`](../tails-pdp/src/stream_attributes.rs) | Liest [`stream-attributes/DEFCON.txt`](../environment/DEFCON.txt) und schreibt `CURRENT_DEFCON`. |
| [`tails-pdp/src/monitor.rs`](../tails-pdp/src/monitor.rs) | Überwacht laufende Prozesse, FDs und Sockets im Userspace. |
| [`tails-pdp/src/fd_revoker.rs`](../tails-pdp/src/fd_revoker.rs) | Schließt fremde File Descriptors per `ptrace` auf x86_64 Linux. |
| [`tails-pdp-common/src/lib.rs`](../tails-pdp-common/src/lib.rs) | Gemeinsame Policy-Datenstrukturen und Auswertungslogik für Kernel und Userspace. |
| [`tails-pdp-ebpf/src/hooks.rs`](../tails-pdp-ebpf/src/hooks.rs) | Einstiegspunkte der eBPF-LSM-Hooks `file_open` und `socket_bind`. |
| [`tails-pdp-ebpf/src/maps.rs`](../tails-pdp-ebpf/src/maps.rs) | Definition der eBPF-Maps. |
| [`tails-pdp-ebpf/src/policies/`](../tails-pdp-ebpf/src/policies/) | eBPF-Policy-Auswertung und Kombinieren der Entscheidungen. |
| [`tails-pdp-admintool/`](../tails-pdp-admintool/) | CLI zum Anzeigen und direkten Bearbeiten gepinnter Maps. |
| [`examples/`](../examples/) | Beispiel-Policies, die nicht automatisch geladen werden. |
| [`policies/`](../policies/) | Aktiver Policy-Ordner, den der Loader überwacht. |
| [`stream-attributes/`](../environment/) | Aktive Stream-Attribute, aktuell `DEFCON.txt`. |

## Kurzzusammenfassung

Der Kernel-Teil entscheidet bei den Hooks `file_open` und `socket_bind`, ob eine Aktion verboten
werden soll. Die Policies liegen in eBPF-Maps. Diese Maps werden durch den Userspace-Loader aus
SAPL-inspirierten Textdateien befüllt. Der Monitor prüft zusätzlich nachträglich laufende Prozesse,
weil eine Policy auch erst aktiv werden kann, nachdem ein Prozess bereits einen Socket oder eine
Datei geöffnet hat [P1], [P3], [P6], [P8], [P14].

---

**Previous:** - | **Next:** [Projektüberblick und Grundbegriffe](01-ueberblick-und-grundbegriffe.md)

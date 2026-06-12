# Offene Punkte und Einschränkungen

Diese Punkte sind beim Lesen des Codes aufgefallen. Sie sind keine direkten Änderungen, sondern
Hinweise für spätere Arbeit.

## Monitor: Dokumentation und Verhalten klar trennen

Der aktuelle Monitor ruft `enforce_violation` für alle Violations auf. Das betrifft nicht nur
Datei-FDs, sondern auch Socket-FDs. In der README steht teilweise eine enger formulierte Aussage zu
Datei-FDs [P6], [P7], [P22].

Vorschlag:

- Entscheiden, ob der Monitor nur melden, nur Datei-FDs schließen oder auch Socket-FDs schließen
  soll.
- Diese Entscheidung im Code und in der README konsistent dokumentieren.

## Admin-Tool kann Policies noch direkt setzen

Die eigentliche Quelle der Wahrheit ist inzwischen [`policies/`](../policies/). Das Admin-Tool kann aber weiterhin
Maps direkt verändern [P3], [P17].

Risiko:

Direkte Änderungen werden beim nächsten erfolgreichen Policy-Sync überschrieben. Das kann für
Nutzer verwirrend sein.

Vorschlag:

- Mutierende Admin-Kommandos als Debug-/Legacy-Funktionen markieren.
- Oder nur noch read-only lassen.

## `policy_loader.rs` enthält ältere Ladefunktionen

[`tails-pdp/src/policy_loader.rs`](../tails-pdp/src/policy_loader.rs) wird aktuell vor allem für `verify_pinned_map_layouts` genutzt. Die
Funktionen `load_file_open_static_policies`, `load_file_open_stream_policies`,
`load_socket_bind_static_policies` und `load_socket_bind_stream_policies` wirken wie ältere
Loader-Funktionen.

Vorschlag:

- Prüfen, ob diese Funktionen noch gebraucht werden.
- Falls nicht, entfernen oder klar als Legacy markieren.

## Tests fehlen weitgehend

Es gibt nur wenige Unit-Tests. Besonders wichtig wären Tests für:

- Parser
- Generationen-Rollback
- Monitor
- Admin-Tool
- Integration mit echtem eBPF auf Linux

Details stehen in [Tests und Teststrategie](09-tests.md).

## Permit-vs-Deny-Konfliktstrategie

`combine.rs` nutzt aktuell Deny-overrides: Sobald `deny != 0`, wird verweigert. `permit` wird zwar
gespeichert, überschreibt Deny aber nicht.

Das ist technisch klar, sollte aber fachlich dokumentiert oder konfigurierbar gemacht werden.

## Prozessname ist begrenzt

Der eBPF-Code nutzt `ctx.command()`, der Monitor liest `Name:` aus `/proc/<pid>/status`. Beide Werte
sind Prozessnamen, keine vollständigen Pfade zur ausführbaren Datei.

Risiko:

Prozessnamen können gekürzt sein oder nicht eindeutig sein.

Vorschlag:

- Später zusätzlich Executable-Pfad, Hash oder Cgroup berücksichtigen.

## Pfadmatching im Kernel

Das Projekt matcht Dateien im Kernel über `device + inode`, nicht über Pfade. Das ist verifier-
freundlich und robust gegen Pfadprobleme, bedeutet aber [P8], [P11], [Q7], [Q22]:

- Hardlinks mit gleichem Inode werden gleich behandelt.
- Wenn eine Datei gelöscht und neu erstellt wird, ändert sich der Inode und alte Policies matchen
  nicht mehr.

## FD-Revocation ist architekturabhängig

`fd_revoker.rs` ist nur für `x86_64 Linux` implementiert. Auf anderen Architekturen gibt die
Funktion einen Fehler zurück.

Vorschlag:

- Architektur explizit dokumentieren.
- Für ARM64 eine separate Implementierung planen, falls nötig.

## Ungültige strukturierte Attribute bleiben ein Bedienrisiko

Der Attribut-Updater ignoriert ungültige Werte in [`environment/system.env`](../environment/system.env)
und behält die letzte gültige Attributgeneration bei [P23]. Das ist robust, kann aber verwirrend
sein, wenn ein Tippfehler nicht sofort als Policy-Verhalten sichtbar wird.

Vorschlag:

- Ungültige Werte weiterhin klar loggen.
- Optional später Status im Admin-Tool anzeigen.

## Keine Ring-Buffer-Events

Es gibt keine Eventübertragung vom Kernel zum Userspace. Das ist bewusst oder zumindest aktuell so.
Der Monitor arbeitet stattdessen pollend über `/proc` [P6], [Q12], [Q13], [Q14].

Grenze:

Kurzlebige Zustände können übersehen werden.

## Zeitbasis ist UTC

Zeitbedingungen wie `environment.utc.hour < 8` nutzen UTC, nicht lokale Zeit.

Vorschlag:

- In Policy-Beispielen und CLI-Hilfe deutlich machen.
- Falls lokale Zeit gewünscht ist, eigene Felder oder Konfiguration ergänzen.

---

**Previous:** [Tests und Teststrategie](09-tests.md) | **Next:** [Glossar](11-glossar.md)

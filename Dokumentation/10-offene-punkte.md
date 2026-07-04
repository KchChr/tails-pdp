# Offene Punkte und Einschränkungen

Diese Punkte sind beim Lesen des Codes aufgefallen. Sie sind keine direkten Änderungen, sondern
Hinweise für spätere Arbeit.

## Tests fehlen weitgehend

Es gibt erste Unit-Tests in `tails-pdp-common`, `tails-pdp-policy-loader`,
`tails-pdp-attribute-loader` und `tails-pdp-userspace-pep`. Weiterhin wichtig sind Tests für:

- Generationen-Rollback
- vollständige Userspace-PEP-Auswertung mit simuliertem `/proc`
- Admin-Tool
- Integration mit echtem eBPF auf Linux

Details stehen in [Tests und Teststrategie](09-tests.md).

## Permit-vs-Deny-Konfliktstrategie

`combine.rs` nutzt aktuell Deny-overrides: Sobald `deny != 0`, wird verweigert. `permit` wird zwar
gespeichert, überschreibt Deny aber nicht.

Das ist technisch klar, sollte aber fachlich dokumentiert oder konfigurierbar gemacht werden.

## Prozessname ist begrenzt

Der eBPF-Code nutzt `ctx.command()`, der Userspace-PEP liest `Name:` aus `/proc/<pid>/status`. Beide Werte
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

Der Attribut-Updater ignoriert ungültige Werte in [`attributes/system.attributes`](../attributes/system.attributes)
und behält die letzte gültige Attributgeneration bei [P23]. Das ist robust, kann aber verwirrend
sein, wenn ein Tippfehler nicht sofort als Policy-Verhalten sichtbar wird.

Vorschlag:

- Ungültige Werte weiterhin klar loggen.
- Optional später Status im Admin-Tool anzeigen.

## Keine Ring-Buffer-Events

Es gibt keine Eventübertragung vom Kernel zum Userspace. Das ist bewusst oder zumindest aktuell so.
Der Userspace-PEP arbeitet stattdessen pollend über `/proc` [P6], [Q12], [Q13], [Q14].

Grenze:

Kurzlebige Zustände können übersehen werden.

## Map-Werte enthalten Rust-Enums

Mehrere `#[repr(C)]`-Map-Strukturen enthalten derzeit `#[repr(u8)]`-Enums und implementieren im
Userspace `aya::Pod`. Die Loader schreiben ausschließlich validierte Werte, und die gepinnten Maps
sind als privilegierte Systemressource vorausgesetzt. Gegen manuell oder durch fremde privilegierte
Programme eingebrachte ungültige Enum-Diskriminanten ist die Darstellung jedoch nicht robust.

Ein späterer ABI-Schritt sollte die Map-Felder auf rohe Integer oder transparente, für jedes
Bitmuster gültige Newtypes umstellen und die Konvertierung an der Auswertungsgrenze validieren. Das
ändert öffentliche gemeinsame Datentypen und das Map-ABI und wurde deshalb nicht als beiläufiges
Refactoring vorgenommen.

## Zeitbasis ist UTC

Zeitbedingungen wie `environment.utc.hour < 8` nutzen UTC, nicht lokale Zeit.

Vorschlag:

- In Policy-Beispielen und CLI-Hilfe deutlich machen.
- Falls lokale Zeit gewünscht ist, eigene Felder oder Konfiguration ergänzen.

---

**Previous:** [Tests und Teststrategie](09-tests.md) | **Next:** [Glossar](11-glossar.md)

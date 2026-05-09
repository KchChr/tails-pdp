# Fehlerbehandlung und Sicherheit

## Fehlerbehandlung im Userspace

Der Userspace-Code nutzt überwiegend `anyhow::Result` und ergänzt Fehler mit Kontext über
`.context(...)` oder `.with_context(...)` [P1], [P3], [P4], [P17].

Beispiele:

- [`tails-pdp/src/main.rs`](../tails-pdp/src/main.rs): fehlende Programme oder Maps werden mit Namen gemeldet.
- [`tails-pdp/src/policy_source.rs`](../tails-pdp/src/policy_source.rs): Parserfehler enthalten Dateiname und Zeile.
- [`tails-pdp/src/policy_loader.rs`](../tails-pdp/src/policy_loader.rs): inkompatible gepinnte Maps nennen erwartete und gefundene Größe.
- [`tails-pdp-admintool/src/lib.rs`](../tails-pdp-admintool/src/lib.rs): ungültige CLI-Werte werden abgelehnt.

Das ist für Debugging wichtig, weil viele eBPF-Fehler sonst schwer verständlich sind.

## Kritische Fehlerfälle

### Inkompatible gepinnte Maps

Wenn Struct-Layouts geändert wurden, passen alte Maps nicht mehr. Das wird in
`policy_loader.rs::verify_pinned_map_layouts` geprüft.

Warum kritisch?

Userspace und Kernel würden sonst dieselben Bytes unterschiedlich interpretieren.

### Fehlgeschlagene Policy-Kompilierung

Wenn eine `.sapl`-Datei nicht geparst werden kann, darf keine halb kaputte Policy-Generation aktiv
werden. `PolicyDirectorySync` hält deshalb die letzte funktionierende Generation aktiv [P3].

### eBPF-Verifier-Fehler

Wenn der Verifier ein Programm ablehnt, startet der Schutz nicht. Verifier-Fehler sind daher
kritisch und sollten immer ernst genommen werden.

### FD-Revocation per `ptrace`

`fd_revoker.rs` verändert kurz die Ausführung eines fremden Prozesses. Das ist mächtig, aber
riskant. Fehler können den Zielprozess stören [P7], [Q15].

Schutzmechanismen im Code:

- PID `0`, PID `1` und der eigene Prozess werden nicht verändert.
- Negative FDs werden abgelehnt.
- Originalregister und Originalinstruktion werden wiederhergestellt.
- `Drop` versucht immer zu detach-en.

## Sicherheitsannahmen

Das Projekt nimmt aktuell an:

- Der Loader läuft mit ausreichenden Rechten.
- Policy-Dateien im Ordner [`policies/`](../policies/) sind vertrauenswürdig.
- Gepinnte Maps unter `/sys/fs/bpf/tails-pdp` gehören zu diesem Programm.
- Der Kernel unterstützt eBPF-LSM.
- `device + inode` identifiziert eine Datei ausreichend eindeutig für die gewünschte Policy.
- Prozessname aus `/proc/<pid>/status` bzw. `bpf_get_current_comm` reicht als Kommando-Merkmal.

## Risiken

| Risiko | Einschätzung | Erklärung |
| --- | --- | --- |
| Fehlerhafte Policy-Datei | Mittel | Kann gewünschte Regeln verhindern. Rollback reduziert das Risiko. |
| Falsche Map-Layouts | Hoch | Kernel und Userspace interpretieren Daten falsch. Layout-Prüfung hilft. |
| `ptrace`-FD-Revocation | Hoch | Greift aktiv in fremde Prozesse ein. |
| Debug-Logging sensibler Daten | Mittel | Trace-Ausgaben können UIDs, Kommandos, Inodes und Ports zeigen. |
| Stream-Policy-Zeitbasis UTC | Niedrig bis Mittel | Nutzer könnten lokale Zeit erwarten. |
| Prozessname als Kommando | Mittel | Prozessnamen können begrenzt, gekürzt oder manipulierbar sein. |

## Logging sensibler Daten

Kernel-Logging ist standardmäßig aus und kann über `TAILS_PDP_EBPF_DEBUG=1` aktiviert werden.

Wenn es aktiv ist, können in `trace_pipe` Informationen erscheinen wie:

- UID
- Kommando
- Device
- Inode
- Port
- Policy-Match-Status

Auf Mehrbenutzersystemen sollte `trace_pipe` nicht dauerhaft offen oder für unbefugte Nutzer
zugänglich sein.

## eBPF-spezifische Sicherheitsgrenzen

eBPF ist sicherer als ein beliebiges Kernelmodul, weil der Verifier Programme vor dem Laden prüft.
Trotzdem gilt [Q7], [Q8], [Q23]:

- Falsche Logik kann legitime Zugriffe blockieren.
- Zu komplexer Code kann vom Verifier abgelehnt werden.
- Nicht jeder Kernel unterstützt dieselben Hilfsfunktionen.
- Kernel-Datenstrukturen können sich zwischen Versionen unterscheiden.

## Verbesserungsbedarf

Siehe auch [Offene Punkte](10-offene-punkte.md).

Besonders wichtig wären:

1. Mehr automatisierte Tests für Parser, Generationen und Monitor.
2. Klarere Trennung zwischen reinem Monitoring und Enforcement.
3. Abstraktion der Map-Zugriffe für bessere Testbarkeit.
4. Dokumentierte Policy-Konfliktstrategie: Deny-overrides oder Permit-overrides.

---

**Previous:** [Policy-Logik und Datenstrukturen](06-policy-logik-und-datenstrukturen.md) | **Next:** [Debugging und Analyse](08-debugging-und-analyse.md)

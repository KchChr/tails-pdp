# Tests und Teststrategie

Das Projekt trennt schnelle, unprivilegierte Prüfungen von privilegierten End-to-End-Tests. Dadurch
kann die Logik auf dem Entwicklungsrechner geprüft werden, während nur der reale Kerneltest das
Laden, Anhängen und Durchsetzen der eBPF-LSM-Programme verifiziert.

## Unprivilegierte Prüfkette

[`test.sh`](../test.sh) führt die normale Prüfkette aus:

```shell
./test.sh
```

Das Skript prüft:

1. Formatierung mit `cargo fmt`.
2. Native Unit-Tests der gemeinsam genutzten Policylogik.
3. Kompilierung der Linux-Testprogramme für Policyloader, Attributloader und Userspace-PEP.
4. Clippy mit `-D warnings`.
5. Den vollständigen Linux-Release-Build einschließlich des eingebetteten eBPF-Objekts.

Die Prüfkette benötigt keine Root-Rechte und verändert keine gepinnten Maps. `test.sh` ist für das
Linux-Zielsystem vorgesehen, weil es die Linux-Testprogramme tatsächlich ausführt. Auf macOS können
dieselben Crates zwar gegen `x86_64-unknown-linux-musl` gebaut werden; die vollständige Ausführung
erfolgt aber erst auf Linux.

## Implementierte Komponententests

### 1. Gemeinsame Policy-Auswertung

Die Tests in [`tails-pdp-common/src/lib.rs`](../tails-pdp-common/src/lib.rs) prüfen die Logik, die
Kernelspace- und Userspace-PEP gemeinsam verwenden:

- vollständiges Matching einer statischen `file_open`-Policy,
- abweichende UID, Command-, Device- oder Inode-Werte,
- `ANY_SUBJECT` für beliebige UIDs,
- Grenzen der UTC-Operatoren,
- Zeit- und DEFCON-Bedingungen,
- den sicheren Umgang mit Modulo `0`,
- Deny-overrides bei mehreren Entscheidungen.

### 2. Parsen und Validieren von Policydateien

Die Tests in
[`tails-pdp-policy-loader/src/policy_source.rs`](../tails-pdp-policy-loader/src/policy_source.rs)
decken unter anderem folgende Fälle ab:

- gültige statische und zeitabhängige `file_open`-Policies,
- rekursives Laden ausschließlich von Dateien mit der Endung `.policy`,
- doppelte Policynamen,
- fehlende Semikolons und unbekannte Actions,
- nicht unterstützte deaktivierte `socket_bind`-Policies,
- zu viele Policies oder dynamische Attributbedingungen,
- ungültige UTC-Komponenten und Modulo `0`.

### 3. Generationen und Rollback

Die Schreiboperationen der Policy-Maps sind über den internen Trait `PolicyGenerationStore`
testbar. Eine In-Memory-Implementierung prüft, dass:

- zuerst die inaktive Bank vollständig geschrieben und erst danach ihre Generation aktiviert wird,
- Schreib- und Aktivierungsfehler die bisher aktive Generation nicht verändern,
- unveränderte sowie bereits fehlgeschlagene Dokumentstände übersprungen werden,
- ungenutzte Einträge einer neuen Bank explizit deaktiviert werden.

Damit wird die zentrale Rollback-Eigenschaft ohne Root-Rechte und ohne echte BPF-Maps getestet.

### 4. Userspace-PEP

Die Tests in [`tails-pdp-userspace-pep/src/pep.rs`](../tails-pdp-userspace-pep/src/pep.rs) verwenden
einen Fake-`FdCloser`. Sie prüfen:

- striktes Parsen numerischer Prozess- und FD-Verzeichnisnamen,
- Erkennung regulärer Datei-FDs und Ignorieren von Verzeichnissen,
- Entzug genau des verletzenden FDs,
- höchstens einen Schließversuch pro FD und Scan,
- unabhängige Behandlung verschiedener FDs,
- Fortsetzung des Scans, wenn ein Schließversuch fehlschlägt,
- ausbleibende Ausführung ohne Trigger,
- expliziten Fehler bei geschlossenem Trigger-Kanal,
- die Berechnung relevanter Stunden- und Modulo-Zeitgrenzen.

Zusätzlich prüfen die Tests in
[`tails-pdp-userspace-common/src/lib.rs`](../tails-pdp-userspace-common/src/lib.rs), dass der
Trigger-Kanal begrenzt ist, schnelle Aktivierungen koalesziert und ein geschlossener Kanal nicht
stillschweigend ignoriert wird. Die Commit-Tests der Loader stellen sicher, dass ein Fehler beim
Schreiben oder Aktivieren keine neue Generation sichtbar macht; damit wird für diesen Pfad auch
kein Trigger erzeugt.

## Privilegierte End-to-End-Tests

[`test-e2e.sh`](../test-e2e.sh) läuft ausschließlich als Root auf einem dafür vorgesehenen
Linux-/NixOS-Zielsystem:

```shell
./test.sh
sudo ./test-e2e.sh
```

Das E2E-Skript startet die echte Release-Runtime in einem isolierten temporären Arbeitsverzeichnis.
Es prüft anschließend:

1. Laden durch den Kernel-Verifier, Anhängen des LSM-Hooks und Vorhandensein der gepinnten Maps.
2. Erlaubten Zugriff ohne Policy.
3. Kernel-Enforcement einer statischen Deny-Policy.
4. Auswertung der aktuellen UTC-Stunde über `CURRENT_TIME`.
5. Ereignisgesteuerte Änderung von `system.defcon`.
6. Rollback auf die letzte gültige Generation nach einem Parserfehler.
7. Nachträgliches Userspace-Enforcement: Nur der verletzende bereits offene FD wird entzogen; ein
   zweiter erlaubter FD desselben Prozesses bleibt offen.

Policydateien werden im Test zunächst vollständig mit einer temporären Endung geschrieben und dann
atomar auf `.policy` umbenannt. So verarbeitet der Dateiwächter keine halbfertigen Dokumente.

### Sicherheitsgrenzen des E2E-Skripts

Der Lauf verändert den globalen BPF-Zustand unter `/sys/fs/bpf/tails-pdp`. Deshalb:

- bricht das Skript ab, wenn bereits eine `tails-pdp`-Runtime läuft,
- beendet es nur selbst gestartete Prozesse,
- entfernt es seine gepinnten Maps beim Aufräumen,
- bewahrt es bei einem Fehler Arbeitsverzeichnis und Runtime-Log zur Diagnose auf.

Das Skript darf nicht auf einem produktiv genutzten Host ausgeführt werden. Auf macOS kann nur die
unprivilegierte Cross-Build-Prüfkette laufen; Verifier, LSM-Attach und reales Enforcement benötigen
den Linux-Zielkernel.

---

**Previous:** [Debugging und Analyse](08-debugging-und-analyse.md) | **Next:** [Offene Punkte und Einschränkungen](10-offene-punkte.md)

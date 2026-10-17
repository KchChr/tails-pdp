# Geführte Terminal-Demo

Vom Repository aus auf dem dedizierten **x86_64-Linux-Zielsystem** starten:

```bash
./scripts/demo.sh
```

Das Skript prüft seine Werkzeuge vor dem Start. Fehlen beispielsweise `tmux`,
Python oder `flock`, startet es sich über `scripts/demo/shell.nix` neu. Nix stellt
die Programme für diesen Aufruf bereit, ohne sie global zu installieren.
`nix-shell` selbst muss bereits verfügbar sein; Paketdownloads benötigen beim
ersten Start gegebenenfalls Netzwerkzugriff. Ein bereits eingerichtetes `sudo`
oder ein Start als root ist für die privilegierte Runtime erforderlich; das
Bereitstellen eines sudo-Pakets richtet keine Systemberechtigungen ein.

Fehlen Release-Binaries, baut das Skript sie automatisch mit
`nix-config/shell.nix`, einschließlich `setup-bpf-tools`. Mit `--build` wird
dieser Build auch bei vorhandenen Binaries durchgeführt. Nach Änderungen am
Rust-Code sollte man diese Option verwenden:

```bash
./scripts/demo.sh --build
```

Vorhandene Binaries eines Cross-Builds lassen sich ebenfalls auswählen:

```bash
TAILS_PDP_BIN=/absoluter/pfad/tails-pdp \
ADM_TOOL_BIN=/absoluter/pfad/tails-pdp-admintool ./scripts/demo.sh
```

Die Kernelvoraussetzungen (BPF-LSM, BTF, eingehängtes bpffs) werden vor dem
Runtime-Start geprüft. Die Nix-Shell kann diese Kernelvoraussetzungen nicht
nachrüsten. Eine andere Runtime, vorhandene Pins oder eine laufende Evaluation
führen zum Abbruch. Der E2E-Runner verwendet die Evaluationssperre nicht;
E2E-Tests daher nicht gleichzeitig starten.

## Bedienung

Das Skript richtet einen eigenen tmux-Server mit drei Bereichen ein:

- **Links:** Erklärungen, vorbereitete Policy-/Attributtexte, Aktionen und Prüfungen.
- **Rechts oben:** vollständiges Runtime-Log mit Aktivierungen und FD-Prüfungen.
- **Rechts unten:** Ergebnisse und FD-Beobachter.

Der Fokus liegt links. **Enter** führt den jeweils erklärten Schritt aus;
weitere Befehle müssen nicht eingegeben werden. **Strg+C** bricht ab. Am Ende
bleibt das Ergebnis bis zum nächsten Enter sichtbar. Maus-Scrollen erlaubt den
Blick auf vorherige Ausgaben; gegebenenfalls mit Escape den tmux-Kopiermodus
verlassen. Das Abkoppeln vom Demo-tmux beendet die Demo und räumt auf. Eine
bereits vorhandene tmux-Sitzung bleibt erhalten.

```bash
./scripts/demo.sh --auto
```

`--auto` führt dieselben Kapitel ohne Enter-Pausen aus und schließt das Layout
nach Abschluss. Auch dieser Modus benötigt ein interaktives Terminal. Technische
Wartephasen prüfen den tatsächlichen Zustand und haben standardmäßig 30 Sekunden
Timeout (`DEMO_TIMEOUT_SECONDS`). Für das Zeitkapitel muss der Timeout über der
zwölfsekündigen Zeitgrenze liegen. Aktivierungszeiten sind keine zugesicherten
Produkteigenschaften: Ein Timeout ist ein Fehler der Vorführung, kein Beleg für
eine garantierte Frist.

## Kapitel

1. Runtime, LSM-Attach, erwartete Maps, Zugriff ohne Deny.
2. Statische Regel mit Real-UID-, Tasknamen- und Ressourcenfilter, einschließlich Negativkontrollen und Hardlink-Abgleich über Geräte-/Inode-Identität.
3. Permit, Deny-Vorrang, Veröffentlichung und Entfernung ohne Neustart.
4. Dynamisches Systemattribut `system.defcon`.
5. Subject-/Resource-Attribute, UND-Verknüpfung, fehlende und anders typisierte Werte.
6. Ungültige Policy und ungültiges Attribut: Generation bleibt erhalten; gültige Korrektur folgt.
7. Selektiver Entzug bereits offener FDs durch Policyaktivierung.
8. Selektiver FD-Entzug allein durch Attributaktivierung, bei unveränderter Policygeneration.
9. Selektiver FD-Entzug allein an einer Zeitgrenze, bei unveränderten Konfigurationsgenerationen.
10. UTC-Zeitbedingungen, Stream-Permit und Deny-Vorrang, abschließende Admin-Inspektion.

Alle Konfigurationen sind auf eine eigens angelegte Datei unter
`/tmp/tpd-demo.XXXXXX/` begrenzt. Die Runtime startet mit diesem Arbeitsverzeichnis;
die Repository-Verzeichnisse `policies/` und `attributes/` werden nicht verändert.
Konfiguration wird mit `scripts/publish-config.sh` atomar veröffentlicht.

`probe.py` dient ausschließlich als Syscall-Helfer: `access` setzt kontrolliert
den Linux-Tasknamen und optional die Real-UID (effektive UID bleibt root) und
unterscheidet LSM-`EPERM` von sonstigen Fehlern. Es werden keine Benutzerkonten
angelegt. `hold` hält drei geschützte und zwei Kontroll-FDs offen und bleibt auch
nach deren Entzug aktiv. Seine Beobachtungen werden zusätzlich zur Runtime-Ausgabe
geprüft. Das Admin-Tool liest Maps; seine Ausgabe allein gilt nicht als
Durchsetzungsnachweis.

Die Demo prüft die gezeigten Funktionsabläufe. Sie ersetzt keine Kapazitäts-,
Performance-, Stabilitäts- oder Race-Tests. FD-Entzug kann gelesene Daten und
bestehende Speicherabbildungen nicht zurückholen; ptrace-Fehler und Races bleiben
Grenzen des Prototyps.

## Ende, Abbruch und Diagnose

Die Demo beendet ihre Hilfsprozesse und Runtime und entfernt ausschließlich die
sechs bekannten, von ihr angelegten Maps. Bestehende Pins werden vorab abgelehnt.
Das Verzeichnis mit `transcript.log`, `runtime.log`, `observer.log`,
`exit-status`, Konfigurationen und FD-Zuständen bleibt für Diagnose erhalten;
sein Pfad wird nach dem Schließen ausgegeben. Status 0 bedeutet, dass alle
Prüfungen erfolgreich waren. Fehler, Abbruch und fehlende Abschlussmeldung
führen zu einem von null verschiedenen Exitstatus.

Unprivilegierte lokale Prüfungen (auch auf macOS):

```bash
bash -n scripts/demo.sh scripts/demo/runner.sh
python3 scripts/tests/test_demo.py
```

Der vollständige Live-Lauf muss auf dem Linux-Zielsystem geprobt werden.

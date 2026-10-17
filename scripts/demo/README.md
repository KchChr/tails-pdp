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
Bereitstellen eines sudo-Pakets richtet keine Systemberechtigungen ein. Deshalb
enthält die Demo-Shell kein sudo-Paket. Die Demo verwendet auf NixOS bevorzugt
`/run/wrappers/bin/sudo` und behält dessen absoluten Pfad auch beim Wechsel in die
Nix-Shell und beim Start des tmux-Workers bei. Bei Bedarf kann `DEMO_SUDO_BIN`
einen anderen absoluten Pfad zu einem eingerichteten System-sudo auswählen.

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

Die Kernelvoraussetzungen (BPF-LSM und BTF) werden vor dem
Runtime-Start geprüft. Die Nix-Shell kann diese Kernelvoraussetzungen nicht
nachrüsten. Der privilegierte Worker startet mit `unshare --mount --propagation
private` in einem eigenen Mount-Namespace und hängt dort ein frisches bpffs unter
`/sys/fs/bpf` ein. Vorhandene Host-Pins bleiben erhalten und blockieren die Demo
nicht. `unshare` und `mount` werden bei Bedarf ebenfalls durch die Nix-Shell
bereitgestellt. Das System muss private Mount-Namespaces und den bpffs-Mount
erlauben. Eine andere Runtime oder eine laufende Evaluation führen weiterhin
zum Abbruch: LSM-Hooks wirken systemweit, auch bei getrennten Pins.
Der E2E-Runner verwendet die Evaluationssperre nicht;
E2E-Tests daher nicht gleichzeitig starten.

## Bedienung

Das Skript richtet einen eigenen tmux-Server mit drei Bereichen ein:

- **Links:** Erklärungen, vorbereitete Policy-/Attributtexte, Aktionen und Prüfungen.
- **Rechts oben:** vollständiges Runtime-Log mit Aktivierungen und FD-Prüfungen.
- **Rechts unten:** Ergebnisse und FD-Beobachter.

Der Fokus liegt links. **Enter** führt den jeweils erklärten Schritt aus.
Danach bleibt die Ausgabe stehen. Ein weiteres **Enter** wechselt zum nächsten
Schritt und leert erst dann den linken Bereich. Nach dessen Erklärung startet
ein erneutes **Enter** die Ausführung. Das gilt auch für die Schritte 7a und 8a;
weitere Befehle müssen nicht eingegeben werden. **Strg+C** bricht ab. Am Ende
bleibt das Ergebnis bis zum nächsten Enter sichtbar. Maus-Scrollen erlaubt den
Blick auf vorherige Ausgaben; gegebenenfalls mit Escape den tmux-Kopiermodus
verlassen. Das Abkoppeln vom Demo-tmux beendet die Demo und räumt auf. Eine
bereits vorhandene tmux-Sitzung bleibt erhalten.

Bei jedem neuen Kapitel (auch 7a und 8a) wird der linke Bereich geleert und der
Cursor an den Anfang gesetzt. Die rechten Bereiche laufen weiter; Scrollback
und gespeicherte Logs bleiben erhalten.

Jedes Kapitel erläutert vor der Ausführung **Ausgangslage**, **Aktion**,
**erwartetes Verhalten** und **worauf in der Ausgabe zu achten ist**. Während
der Ausführung erklären zusätzliche Hinweise die einzelnen Policy- und
Attributwechsel sowie ihre Bedeutung für die anschließenden Prüfungen.
Begriffe wie FD, Generation und `allow`/`deny` werden im Ablauf erklärt.
Vor jeder sichtbaren Admin-Ausgabe erscheint der tatsächlich ausgeführte
Aufruf mit Binärpfad, Quellverzeichnissen und Unterbefehl als `$ ...`.
Die Befehle laufen im privilegierten Demo-Worker; Eingaben sind nicht nötig.
Interne Generationsabfragen bleiben ohne Befehlsausgabe. Kapitel 2 nennt die
vollständigen Pfade von `protected.txt`, `control.txt` und dem Hardlink `alias.txt`.
Auch die Zugriffshilfe wird mit vollständigem Aufruf gezeigt: `probe.py access`
führt eine echte Dateiöffnung aus und gibt `allow` oder `deny` zurück. Die Demo
kennzeichnet diese Rückgabe mit `[probe.py access → stdout]`. Die anschließenden
`[Demo-Prüfung] OK: ...`-Zeilen erzeugt das Bashskript nach dem Vergleich mit dem
erwarteten Ergebnis; sie stammen nicht aus dem Admin-Tool oder dem Runtime-Log.
Die Ausgaben des FD-Beobachters tragen `[FD-Beobachter: probe.py hold]`, und
Admin-Ausgaben werden mit `[Admin-Tool: tails-pdp-admintool]` eingeleitet.
Die Kapitel sind auch direkt in `demo_worker()` in `scripts/demo/runner.sh`
kommentiert. Im Zeitkapitel erfolgt die gesamte Erklärung vor dem Berechnen
der Zeitgrenze, damit die Vorführungsdauer den Übergang nicht vorwegnimmt.

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
sechs bekannten, von ihr angelegten Maps im eigenen bpffs. Nach dem Ende aller
Worker-Prozesse verschwindet dessen privater Mount-Namespace automatisch.
Host-Pins werden weder entfernt noch überschrieben.
Das Verzeichnis mit `transcript.log`, `runtime.log`, `observer.log`,
`exit-status`, Konfigurationen und FD-Zuständen bleibt für Diagnose erhalten;
sein Pfad wird nach dem Schließen ausgegeben. Status 0 bedeutet, dass alle
Prüfungen erfolgreich waren. Fehler, Abbruch und fehlende Abschlussmeldung
führen zu einem von null verschiedenen Exitstatus.

Unprivilegierte lokale Prüfungen (auch auf macOS):

```bash
bash -n scripts/demo.sh scripts/demo/runner.sh scripts/demo/dependencies.sh
python3 scripts/tests/test_demo.py
```

Diese Prüfungen laufen automatisch über `./scripts/test.sh`. Nach Release-Build,
E2E-Tests und Evaluation führt die Prüfkette zusätzlich die vollständige Demo mit
echtem tmux und `--auto` in einem Pseudoterminal aus. Damit funktioniert der Test
auch mit umgeleiteter Konsolenausgabe und ohne manuellen Tastendruck.

Einzellauf auf dem dedizierten Linux-Zielsystem mit vorhandenen Release-Binaries:

```bash
sudo env "PATH=$PATH" python3 scripts/tests/test_demo_live.py
```

Der Live-Test verlangt Exitstatus 0 von Launcher und Worker, die Abschlussmeldung
aller Kapitel und die Bestätigung des privaten bpffs. Er prüft außerdem, dass die
Namen, Inodes und Modi vorhandener Host-Pins unverändert bleiben. Ist auf dem Host
bpffs eingehängt, erzeugt er darin ein eigenes temporäres Testverzeichnis, um den
Start trotz vorhandener Einträge gezielt zu prüfen; dieses Verzeichnis wird
anschließend wieder entfernt. Der Map-Inhalt fremder Pins wird nicht ausgelesen.

Ein Gesamtzeitlimit von 300 Sekunden verhindert unbegrenztes Warten. Bei Bedarf
ist es über `DEMO_TEST_TIMEOUT_SECONDS` anpassbar. Beim Timeout wird die Demo erst
mit SIGTERM zum Aufräumen aufgefordert und nach einer Schonfrist zwangsweise
beendet. Ein Timeout gilt immer als Fehler.

Die Prüfkette speichert `demo/report.json`, `demo/terminal.log` (mit
Terminal-Steuersequenzen) und `demo/fixture/` unter ihrem Ergebnisverzeichnis.
Auch bei Fehlern werden verfügbare Demo-Artefakte kopiert. Beim direkten Aufruf
ohne `TAILS_PDP_TEST_RESULTS_DIR` liegen die Nachweise unter einem ausgegebenen
`/tmp/tails-demo-test-...`-Verzeichnis. Die kurzen Laufzeitpfade bleiben erhalten.

# Geführte Terminal-Demo

Vom Repository aus auf dem dedizierten **x86_64-Linux-Zielsystem** starten:

```bash
./scripts/demo.sh
```

Mit der Systemkonfiguration aus `nix-config/configuration.nix` sind die
Laufzeitwerkzeuge einschließlich `tmux` bereits systemweit verfügbar. Eine
Nix-Shell muss vor dem Start nicht manuell geöffnet werden. Fehlen die
Release-Binaries oder wird `--build` verwendet, ruft das Skript die
Nix-Entwicklungsumgebung für den Build automatisch auf. Der Build verwendet
`scripts/demo/build.sh`, die lokalen Rust-Quellen aus `vendor/` und
`cargo build --frozen`. Cargo-Downloads sind auch für die verschachtelten
eBPF-Builds deaktiviert. Vor dem Build prüft `scripts/check-vendor.py` sämtliche
Dateien anhand der mitgelieferten Cargo-Prüfsummen. Der Shell-Hook installiert
keine Werkzeuge mehr; `RUSTUP_AUTO_INSTALL=0` verhindert auch implizite
Toolchain-Installationen durch Rustup.

Die Quellen umfassen auch die in `nix-config/ebpf-sysroot/` festgelegten
Registry-Abhängigkeiten der Rust-Systembibliothek. Diese werden beim
eBPF-Build von `core` zusätzlich zu den Projektabhängigkeiten benötigt.
Die Prüfroutine gleicht außerdem das Lockfile der installierten
`rust-src`-Komponente mit dieser mitgelieferten Liste ab.

**Stand der Offline-Abgabe:** Die Cargo-Abhängigkeiten sind lokal vorhanden.
Ein vollständiges Offline-Paket der Buildwerkzeuge ist noch nicht mitgeliefert.
Die in `nix-config/rust-toolchain` und `nix-config/ebpf-toolchain` festgelegten
Compiler, `rust-src`, BPF-Linker 0.9.15 und die LLVM-21-Bibliotheken müssen lokal
vorhanden sein. Der aktuelle Aya-eBPF-Build benötigt weiterhin Nightly;
die Anforderung, auch den eBPF-Teil ausschließlich mit Stable Rust zu bauen,
ist damit noch nicht erfüllt. Es wird weder eine Nightly-Installation noch
ein `RUSTC_BOOTSTRAP`-Workaround während der Demo ausgeführt.

Das Skript prüft seine Werkzeuge vor dem Start. Fehlen beispielsweise `tmux`,
Python oder `flock`, startet es sich über `scripts/demo/shell.nix` neu. Nix stellt
die Programme für diesen Aufruf bereit, ohne sie global zu installieren.
`nix-shell`, die lokale Nixpkgs-Quelle und alle benötigten Nix-Store-Pfade müssen
bereits verfügbar sein. Substitutionen sowie lokale und entfernte Nix-Builds
sind für diese Aufrufe deaktiviert; fehlende Pakete führen zum Abbruch.
Die lokale Nixpkgs-Quelle ist bisher noch nicht im Repository gepinnt oder
mitgeliefert. Ein bereits eingerichtetes `sudo`
oder ein Start als root ist für die privilegierte Runtime erforderlich; das
Bereitstellen eines sudo-Pakets richtet keine Systemberechtigungen ein. Deshalb
enthält die Demo-Shell kein sudo-Paket. Die Demo verwendet auf NixOS bevorzugt
`/run/wrappers/bin/sudo` und behält dessen absoluten Pfad auch beim Wechsel in die
Nix-Shell und beim Start des tmux-Workers bei. Bei Bedarf kann `DEMO_SUDO_BIN`
einen anderen absoluten Pfad zu einem eingerichteten System-sudo auswählen.

Fehlen Release-Binaries, baut das Skript sie automatisch mit
`nix-config/shell.nix` und `scripts/demo/build.sh`. Mit `--build` wird
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
- **Rechts oben:** Runtime-Log mit Aktivierungen und FD-Prüfungen sowie gefilterte Kernel-Debugausgaben.
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

Die Ausgabe verwendet ein einheitliches Farbschema:

- **Türkis, fett:** Kapitelüberschriften; Abschnittsüberschriften sind fett.
- **Gelb:** ausgeführte Befehle mit `$` sowie die Enter-Aufforderungen.
- **Hellblau:** Admin-Ausgaben, Rückgaben der Zugriffshilfe und FD-Beobachtungen.
- **Magenta:** veröffentlichte Policy- und Attributtexte.
- **Grün:** bestätigte Demo-Prüfungen, auch bei einem erwarteten `deny`.
- **Rot:** Fehler der Demo oder eine Abweichung vom erwarteten Ergebnis.

Eine dauerhaft sichtbare zweite tmux-Statuszeile zeigt diese Legende auch nach
dem Leeren des linken Bereichs. Die obere Statuszeile enthält die Bedienhinweise.

Erklärungstexte bleiben in der normalen Terminalfarbe. Quellenkennzeichnungen
und Prüfergebnisse bleiben zusätzlich als Text erhalten. Farben lassen sich mit
`NO_COLOR=1 ./scripts/demo.sh` deaktivieren und werden bei `TERM=dumb` oder ohne
Terminal ebenfalls abgeschaltet. Die Demo-Mitschnitte enthalten bei aktivierten
Farben ANSI-Steuersequenzen; maschinenlesbare FD-Zustände und interne
Generationsabfragen bleiben unverändert.

Jedes Kapitel erläutert vor der Ausführung **Ausgangslage**, **Aktion**,
**erwartetes Verhalten** und **Beobachtung**. Während
der Ausführung erklären zusätzliche Hinweise die einzelnen Policy- und
Attributwechsel sowie ihre Bedeutung für die anschließenden Prüfungen.
Begriffe wie FD, Generation und `allow`/`deny` werden im Ablauf erklärt.
Vor jeder sichtbaren Admin-Ausgabe erscheint der entsprechende Aufruf mit
Binärpfad, Quellverzeichnissen und Unterbefehl als `$ ...`. Pfade innerhalb des
Repositorys werden relativ angezeigt, beispielsweise
`./target/release/tails-pdp-admintool --policy-dir ./policies --attributes-dir ./attributes show-active`.
Das Administrationstool wird in der gesamten Demo ausschließlich mit
`show-active` aufgerufen. Dadurch werden nur aktivierte Policies und die
aktuellen Attribute angezeigt, keine deaktivierten Policy-Plätze.
Die Befehle laufen im privilegierten Demo-Worker; Eingaben sind nicht nötig.
Interne Generationsabfragen bleiben ohne Befehlsausgabe. Kapitel 2 nennt die
Pfade `demo/files/protected.txt`, `demo/files/control.txt` und `demo/files/alias.txt`.
Auch die Zugriffshilfe wird mit vollständigem Aufruf gezeigt: `probe.py access`
führt eine echte Dateiöffnung aus und gibt `allow` oder `deny` zurück. Die Demo
kennzeichnet diese Rückgabe mit `[probe.py access → stdout]`. Die anschließenden
`[Demo-Prüfung] OK: ...`-Zeilen erzeugt das Bashskript nach dem Vergleich mit dem
erwarteten Ergebnis; sie stammen nicht aus dem Admin-Tool oder dem Runtime-Log.
Die Ausgaben des FD-Beobachters tragen `[FD-Beobachter: probe.py hold]`, und
Admin-Ausgaben werden mit `[Admin-Tool des Prototyps]` eingeleitet.
Kernel-Debugmeldungen tragen `[Kernelspace-PEP]`. Die Runtime kennzeichnet den
Userspace-PEP mit der Logkennung `USERSPACE_PEP`, etwa beim erfolgreichen oder
fehlgeschlagenen Schließen eines FDs. Beide Durchsetzungspfade enthalten eine
integrierte PDP-Funktion, die Policies auswertet und eine Entscheidung ableitet.
Die Komponenten heißen entsprechend der Thesis Kernelspace-PEP und Userspace-PEP.
Die Kapitel sind auch direkt in `demo_worker()` in `scripts/demo/runner.sh`
kommentiert. Im Zeitkapitel erfolgt die gesamte Erklärung vor dem Berechnen
der Zeitgrenze, damit die Vorführungsdauer den Übergang nicht vorwegnimmt.
In Kapitel 3 wird die Ausgangslage zusätzlich vor dem Ausführen der Aktionen
mit einem sichtbaren `show-active`-Aufruf belegt. Dabei sind keine aktivierten
Policy-Einträge vorhanden; die unabhängig verwalteten Attribute bleiben sichtbar.
Die Erläuterungen verwenden durchgehend Policies und Policy-Stand für die
geladenen Zugriffsrichtlinien.

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
2. Statische Policy mit Real-UID-, Kommando- und Ressourcenfilter, einschließlich Negativkontrollen und Hardlink-Abgleich über Geräte-/Inode-Identität.
3. Permit, Deny-Vorrang, Veröffentlichung und Entfernung ohne Neustart.
4. Dynamisches Systemattribut `system.defcon`.
5. Subject-/Resource-Attribute, UND-Verknüpfung, fehlende und anders typisierte Werte.
6. Ungültige Policy und ungültiges Attribut: Generation bleibt erhalten; gültige Korrektur folgt.
7. Selektiver Entzug bereits offener FDs durch Policyaktivierung.
8. Selektiver FD-Entzug allein durch Attributaktivierung, bei unveränderter Policygeneration.
9. Selektiver FD-Entzug allein an einer Zeitgrenze, bei unveränderten Konfigurationsgenerationen.
10. UTC-Zeitbedingungen, Stream-Permit und Deny-Vorrang, abschließende Admin-Inspektion.

Die Demo startet mit dem Repository als Arbeitsverzeichnis. Die Runtime liest
ihre Konfiguration aus `policies/` und `attributes/`; die Beispieldateien liegen
unter `demo/files/`. Jeder Lauf erhält ein eigenes Verzeichnis
`demo/runs/run.XXXXXX/` für Logs, FD-Zustände und vorbereitete Dateien. `demo/`
ist in Git ausgeschlossen. Die angezeigten Befehle verwenden kurze relative
Pfade. Nur `resource.path` in den Policies muss weiterhin ein absoluter Pfad
sein; er darf einschließlich Repositorypfad höchstens 64 Byte umfassen.

Damit die Ausgangslage reproduzierbar ist, werden vorhandene Verzeichnisse
`policies/`, `attributes/` und `demo/files/` vorübergehend unter
`demo/runs/run.XXXXXX/original/` gesichert. Anschließend werden die
Demo-Verzeichnisse angelegt. Nach dem Beenden der Runtime werden die
Demo-Konfigurationen und Beispieldateien ins Laufverzeichnis verschoben und die
Originalverzeichnisse wiederhergestellt. README-Dateien und vorhandene
Konfigurationen bleiben dadurch erhalten. Während der Demo sollten die
gesicherten Originale nicht bearbeitet werden.

Die Markierung `demo/.workspace-active/backup-path` nennt den Sicherungspfad.
Nach einem nicht abfangbaren Abbruch (etwa SIGKILL oder VM-Ausfall) wird beim
nächsten Start automatisch versucht, die dort genannten Originalverzeichnisse
wiederherzustellen. Die Sperre muss dafür frei sein und es darf kein Prototyp
mehr laufen. Aktuell vorhandene Demo-Verzeichnisse werden zuvor unter
`demo/runs/<neuer Lauf>/recovered.XXXXXX/` archiviert; die frühere Markierung
bleibt dort ebenfalls erhalten. Es werden keine vorhandenen Dateien gelöscht.
Das Manifest `original/directories.present` hält fest, welche Verzeichnisse vor
einem Lauf existierten. Bei älteren Sicherungen ohne dieses Manifest werden nur
tatsächlich vorhandene Originalsicherungen zurückgestellt; Verzeichnisse ohne
eindeutige Zuordnung bleiben erhalten. Ungültige oder fehlende Sicherungspfade
führen weiterhin zu einem Abbruch mit Diagnose. Konfiguration wird während der
Demo mit `scripts/publish-config.sh` atomar veröffentlicht.

`probe.py` dient ausschließlich als Syscall-Helfer: `access` setzt kontrolliert
den unter Linux geführten Kommandonamen `comm` für den Kommando-Filter und optional die Real-UID (effektive UID bleibt root) und
unterscheidet LSM-`EPERM` von sonstigen Fehlern. Es werden keine Benutzerkonten
angelegt. `hold` hält drei geschützte und zwei Kontroll-FDs offen und bleibt auch
nach deren Entzug aktiv. Seine Beobachtungen werden zusätzlich zur Runtime-Ausgabe
geprüft. Das Admin-Tool liest Maps; seine Ausgabe allein gilt nicht als
Durchsetzungsnachweis.

Die Demo prüft die gezeigten Funktionsabläufe. Sie ersetzt keine Kapazitäts-,
Performance-, Stabilitäts- oder Race-Tests. FD-Entzug kann gelesene Daten und
bestehende Speicherabbildungen nicht zurückholen; ptrace-Fehler und Races bleiben
Grenzen des Prototyps.

## Kernel-Debugausgabe

Die Demo startet den Prototyp mit `TAILS_PDP_EBPF_DEBUG=deny`. Im Kernel
entstehen damit ausschließlich endgültige Deny-Meldungen und Tail-Call-Fehler.
UID-, Permit- und Auswertungszwischenstände werden bereits vor `bpf_printk`
unterdrückt und belegen keinen Trace-Pufferplatz. Der bisherige Wert `1`
aktiviert weiterhin das ausführliche Debuglogging; `0` deaktiviert es.

Nach dieser Änderung müssen die Binaries einschließlich eBPF-Objekt neu gebaut
werden, beispielsweise mit `./scripts/demo.sh --build`. Die Demo prüft beim
Start die Runtime-Bestätigung `Kernel debug logging mode=Deny` und bricht bei
einem alten oder falsch konfigurierten Binary mit einem Build-Hinweis ab.

Ein eigener Leser
(`scripts/demo/kernel_trace.py`) übernimmt die `bpf_printk`-Meldungen aus
`trace_pipe` in das obere rechte Fenster. Sichtbar sind endgültige
Deny-Entscheidungen des Kernelspace-PEP (`file_open final=deny`) und fehlgeschlagene
Tail-Calls, die zur Ablehnung führen. Der Anzeigefilter bleibt zusätzlich aktiv,
um sonstige Meldungen aus dem gemeinsam genutzten Trace-Stream auszublenden. Die ursprüngliche
Trace-Zeile einschließlich vorhandener Prozess- und Zeitangaben bleibt erhalten.

Vor dem Start wird tracefs innerhalb des privaten Mount-Namespace unter dem
Laufverzeichnis eingehängt. `tracing_on` und `options/trace_printk` werden für
die Demo aktiviert und beim regulären Ende oder einem abgefangenen Abbruch auf
ihre vorherigen Werte zurückgesetzt. Die Kernel-Unterstützung für tracefs und
`bpf_printk` muss vorhanden sein. Fehler beim Einrichten des Lesers brechen die
Demo mit einer Diagnose ab.

Der Mount ist privat; die Tracing-Einstellungen und der Kernel-Trace-Puffer sind
jedoch gemeinsam genutzter Kernelzustand. Das Lesen aus
[`trace_pipe`](https://docs.kernel.org/trace/ftrace.html#trace-pipe) konsumiert
Einträge. Deshalb ist während der Demo auf der vorgesehenen VM kein weiterer
Trace-Leser zu betreiben. Alte Einträge werden vor dem Start des Prototyps
verworfen. Eventverluste werden als `[Kernel-Debug]` gemeldet. Die Ausgabe ist
eine Debughilfe und kein vollständiges Auditprotokoll; zusätzliche Protokollierung
verändert auch das Laufzeitverhalten. Für Performance-Messungen ist diese
Demo-Konfiguration nicht vorgesehen.

## Ende, Abbruch und Diagnose

Die Demo beendet ihre Hilfsprozesse und Runtime und entfernt ausschließlich die
sechs bekannten, von ihr angelegten Maps im eigenen bpffs. Nach dem Ende aller
Worker-Prozesse verschwindet dessen privater Mount-Namespace automatisch.
Host-Pins werden weder entfernt noch überschrieben.
Das Verzeichnis mit `transcript.log`, `runtime.log`, `kernel.log`, `observer.log`,
`exit-status`, Konfigurationen und FD-Zuständen bleibt unter `demo/runs/` für Diagnose erhalten;
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
aller Kapitel, die Bestätigung des privaten bpffs und mindestens eine
Deny-Entscheidung des Kernelspace-PEP in `kernel.log`. Ein falscher Loggingmodus oder
gemeldete Trace-Verluste lassen den Live-Test fehlschlagen. Er prüft außerdem, dass die
Namen, Inodes und Modi vorhandener Host-Pins unverändert bleiben. Ist auf dem Host
bpffs eingehängt, erzeugt er darin ein eigenes temporäres Testverzeichnis, um den
Start trotz vorhandener Einträge gezielt zu prüfen; dieses Verzeichnis wird
anschließend wieder entfernt. Der Map-Inhalt fremder Pins wird nicht ausgelesen.
Zusätzlich werden die ursprünglichen Konfigurations- und Dateiverzeichnisse vor
und nach der Demo anhand ihrer Einträge, Inodes, Modi und Datei-Prüfsummen
verglichen, um die unveränderte Wiederherstellung zu prüfen.

Ein Gesamtzeitlimit von 300 Sekunden verhindert unbegrenztes Warten. Bei Bedarf
ist es über `DEMO_TEST_TIMEOUT_SECONDS` anpassbar. Beim Timeout wird die Demo erst
mit SIGTERM zum Aufräumen aufgefordert und nach einer Schonfrist zwangsweise
beendet. Ein Timeout gilt immer als Fehler.

Die Prüfkette speichert `demo/report.json`, `demo/terminal.log` (mit
Terminal-Steuersequenzen) und `demo/fixture/` unter ihrem Ergebnisverzeichnis.
Auch bei Fehlern werden verfügbare Demo-Artefakte kopiert. Beim direkten Aufruf
ohne `TAILS_PDP_TEST_RESULTS_DIR` liegen die Nachweise unter einem ausgegebenen
`test-results/demo-...`-Verzeichnis im Repository. Die Demo selbst verwendet auch
im Live-Test die Repository-Verzeichnisse und sichert deren ursprüngliche Inhalte.

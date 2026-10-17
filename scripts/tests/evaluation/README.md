# Ergänzende Evaluation

Die vollständige Prüfkette wird auf dem dedizierten Linux-Testsystem über einen einzigen
Einstieg gestartet:

```bash
./scripts/test.sh
```

Das Skript führt zunächst Formatierung, Rust-Tests, Clippy und Release-Build ohne erhöhte
Berechtigungen aus. Für die anschließenden Kernel- und Evaluationsszenarien fordert es selbst
über `sudo` Root-Rechte an. Die Teilrunner können für gezielte Wiederholungen weiterhin direkt
aufgerufen werden:

```bash
sudo ./scripts/tests/test-evaluation.sh
# Einzelne IDs sind ebenfalls möglich:
sudo ./scripts/tests/test-evaluation.sh E2E-11 COMP-04 PERF-02
```

Die Prüfkette enthält außerdem Demo-Regressionstests und abschließend einen
vollständigen Live-Test von `scripts/demo.sh --auto` mit echtem tmux unter einem
Pseudoterminal. Dieser Test ist kein Evaluationsszenario mit eigener E2E-ID.
Bericht, Terminalmitschnitt und Fixture werden unter `test-results/<Lauf>/demo/`
gespeichert. Details und Einzellauf stehen in
[`scripts/demo/README.md`](../../demo/README.md).

COMP-01 bis COMP-03 laufen als Rust-Komponententests im ersten Teil von `./scripts/test.sh`.
COMP-04 verwendet echte Maps und benötigt deshalb hier Root.
`sudo ./scripts/tests/test-e2e.sh` führt jetzt E2E-01 bis E2E-19 aus. Die ersten zehn
verwenden ihre bisherige gemeinsame Fixture, die neun weiteren jeweils eine
isolierte Runtime. Die zusätzlichen Szenarien sind auch einzeln startbar:

```bash
sudo bash scripts/tests/e2e/E2E-12.sh
sudo bash scripts/tests/evaluation/LOAD-01.sh
```

## Wo liegt welcher Test?

| Dateien | Inhalt |
|---|---|
| `scripts/tests/e2e/E2E-11.sh` bis `E2E-14.sh` | Policy-, Attribut- und Admin-Prüfschritte direkt in Bash |
| `scripts/tests/e2e/E2E-15.sh` | UID-Szenario in Bash; `access.py` führt `setresuid` und `open` aus |
| `scripts/tests/e2e/E2E-16.sh` | Mehrfachentzug in Bash; `fd_probe.py` hält und beobachtet die FDs |
| `scripts/tests/e2e/E2E-17.sh` | Bash-Wrapper für `scripts/tests/evaluation/E2E-17.py`; koordiniert zwei Hilfsprozesse und hält den ptrace-Tracer im selben Pythonprozess |
| `scripts/tests/e2e/E2E-18.sh`, `E2E-19.sh` | Bash-Einstiege für `dynamic_fd.py`; realer FD-Entzug allein durch Attributaktivierung bzw. Zeitgrenze |
| `scripts/tests/evaluation/COMP-04.sh`, `LOAD-01.sh`, `STAB-01.sh` | Admin-, Kapazitäts- und Stabilitätsprüfungen direkt in Bash |
| `scripts/tests/evaluation/CHAR-01.sh`, `RACE-01.sh` | Ablauf und Assertions in Bash; FD-/fork-/mmap-Operationen in `fd_probe.py` |
| `scripts/tests/evaluation/PERF-01.sh` bis `PERF-03.sh` | Je ein Bash-Wrapper für die gleichnamige Pythondatei; monotone Zeitmessung ohne Shell-Prozessstart pro Messpunkt |

`shell.sh` enthält gemeinsame Bash-Hilfsfunktionen; `support.py` stellt die
Runtime-/FD-Infrastruktur für die Pythonhelfer bereit. `run.py` enthält nur noch
Fixture-Verwaltung, Aufruf der Bashdateien und Berichterstellung, keine zentral
versteckten Szenariofunktionen. Der bisherige direkte Aufruf über Python bleibt
kompatibel. Jeder neue Test hat genau einen Bash-Einstiegspunkt.

Die Bash-Szenarien verwenden `access.py` zusätzlich als kleinen Syscall-Helfer,
um ausschließlich `EPERM` als LSM-Deny zu akzeptieren. Ein beliebiger fehlgeschlagener
`cat`-Aufruf genügt weiterhin nicht als Nachweis.

Jedes zusätzliche Szenario startet eine eigene Runtime mit temporären Dateien.
Vorhandene Runtime-Prozesse oder bekannte gepinnte Maps führen zum Abbruch.
Die Suite entfernt beim Aufräumen nur ihre bekannten Maps und eigenen Prozesse.
Testsuiten dürfen nicht parallel gestartet werden. Die Evaluation verwendet eine
Sperrdatei; der Runner `scripts/tests/test-e2e.sh` kennt diese Sperre nicht.

Bei `./scripts/test.sh` werden der vollständige Konsolenmitschnitt, Schritt- und Gesamtexitstatus sowie
Quellstand und Systemangaben unter `test-results/<UTC-Zeitstempel>-<eindeutiger Suffix>/`
im Repository gespeichert. Die gemeinsame E2E-Umgebung wird unter `e2e-shared/` archiviert,
die isolierten Szenarioläufe unter `evaluation/tails-eval-.../`. Auch fehlgeschlagene Läufe
bleiben erhalten. Für die Thesis verwendete Läufe werden mit ihrem vollständigen Nachweisordner archiviert.

Während der Ausführung bleiben die kurzen Fixture-Pfade unter `/tmp`, damit längere
Repository-Pfade nicht die Policy-Pfadgrenze überschreiten oder die Messungen verändern.
Beim direkten Aufruf der einzelnen Runner bleiben die Artefakte wie bisher unter
dem ausgegebenen `/tmp/tails-eval-...` erhalten:
`report.json`, Runtime- und Kernel-Logs, Hilfsprozessergebnisse und Fehlerdetails.
Exitstatus 1 bedeutet mindestens einen fehlgeschlagenen Test. Insbesondere
bekannte Produktfehler werden nicht als bestandene Tests behandelt.

E2E-18 installiert zunächst eine noch nicht passende Deny-Policy (`system.defcon <= 2`)
und öffnet drei geschützte sowie zwei weiterhin zulässige Kontroll-FDs. Anschließend
wird ausschließlich `defcon` von 5 auf 2 geändert. Der Test verlangt einen Scan mit
Attributaktivierung als Ursache, eine geänderte Attributgeneration, eine unveränderte
Policygeneration und den selektiven Entzug aller drei geschützten FDs.

E2E-19 verwendet `environment.time % 4294967296 >= <Zeitgrenze>` mit einer Grenze
zehn Sekunden in der Zukunft. Nach der Einrichtung bleiben Policy- und Attributdateien
unverändert; die Systemuhr wird nicht verstellt. Der Test verlangt einen zeitgetriggerten
Scan, unveränderte Policy-/Attributgenerationen und den selektiven Entzug nach Erreichen
der Grenze. Eine zu langsame Einrichtung wird ausdrücklich als Fehler gemeldet, damit
ein bereits beim Öffnen unzulässiger Zugriff nicht als Zeitübergangstest durchgeht.
Beide Szenarien prüfen vor dem Auslöser die FD-Identitäten und speichern Generationen,
Auslöser und Probe-Ergebnisse in `detail.json`. Ein Timeout oder geschlossener Kontroll-FD
lässt den Test fehlschlagen. Die Implementierung der Tests ist noch kein Nachweis ihres
Bestehens auf dem Zielsystem; dafür sind die tatsächlich erzeugten Laufartefakte nötig.

Gezielter Lauf beider neuen Szenarien mit zuvor gebauten aktuellen Binaries:

```bash
sudo ./scripts/tests/test-evaluation.sh E2E-18 E2E-19
```

Standard: zehn Wiederholungen pro Latenz-/Race-Test, 100 Stabilitätszyklen.
Anpassung z.B. `sudo env EVAL_REPEATS=30 EVAL_STAB_CYCLES=500 ./scripts/tests/test-evaluation.sh`.
Die Ausgaben dokumentieren die tatsächlich verwendeten Parameter.

PERF-01 misst 20.000 warme `os.open`-Aufrufe je Zustand, inklusive Python- und
Timeraufwand, ohne `close`. Der Vergleich ist ein sequenzieller Mikrobenchmark,
keine isolierte Messung ausschließlich des Hooks. PERF-02 beobachtet mit 10 ms
Polling die neue Entscheidung. PERF-03 beobachtet EBADF mit 1 ms Polling. Die neue
Messfassung bereitet die Policy außerhalb des überwachten Verzeichnisses auf demselben
Dateisystem vor und misst ab der abschließenden Umbenennung. Vor jedem Versuch müssen
der Policy-Watcher nachweislich in asynchrones Warten zurückgekehrt und alle begonnenen
Scans abgeschlossen sein; die Messmarkierungen müssen anschließend 300 ms stabil bleiben.
Ein vor dem Messstart empfangenes Ereignis, zusätzliche Ereignisphasen oder eine ungültige
zeitliche Reihenfolge lassen die Messung fehlschlagen. Eine Debounce-Phase existiert nicht mehr.

Der Runner aktiviert nur für PERF-03 `TAILS_PDP_TIMING=1`. Aktuelle Binaries sind dafür
neu zu bauen. Die optionalen Marker verwenden Linux `CLOCK_MONOTONIC`, ebenso wie
Python `monotonic_ns()`. Erfasst werden Empfang des Änderungsereignisses im Userspace,
Beginn und Ende des Map-Systemaufrufs zur Aktivierung sowie
der von der FD-Probe beobachtete EBADF-Zeitpunkt. Die Aktivierung bleibt ein Intervall;
der Ereigniszeitpunkt bezeichnet den Empfang, nicht die Erzeugung im Kernel. Marker
und Protokollierung verursachen zusätzlichen Messaufwand. Deshalb sind neue Ergebnisse
als instrumentierte Messung auszuweisen und nicht ungekennzeichnet mit den bisherigen
PERF-03-Werten zu vermischen. `detail.json` enthält alle Phasenzeitpunkte und Generationen.
Die lokale Auswertung ist mit `python3 scripts/tests/evaluation/test_perf03.py` prüfbar; dies
ersetzt den privilegierten Messlauf nicht.
Die Rohdaten und Median/p95/p99 werden gespeichert. Bei zehn Wiederholungen
entsprechen hohe Perzentile praktisch dem Maximum und sind nur deskriptiv.

LOAD-01 prüft je 16 statische und Stream-Policies sowie 512 Attribute pro Bank
(1024 Map-Einträge insgesamt für zwei Banken). Der Versuch mit 513 Attributen bei
512 Einträgen in der aktiven Bank wird vor dem Schreiben abgelehnt. LOAD-01
vergleicht danach Generationsnummern und aktive Attributwerte, prüft weiterhin
wirksames Deny und anschließend zwei erfolgreiche Updates ohne Neustart
(Deny–Allow–Deny). Die Runtime muss durchgehend aktiv bleiben.

Die Kapazitätsprüfung verwendet die tatsächliche Größe der gepinnten Map und die
Einträge außerhalb der zu ersetzenden Bank. 512 ist keine feste Obergrenze pro
Generation: Größere Generationen sind möglich, wenn der verbleibende aktive
Stand ausreichend Platz lässt. Bei einem fehlgeschlagenen Update bleiben aktive
Generation und letzter erfolgreich geladener Stand erhalten. Ein späteres
Dateiereignis kann einen erneuten Versuch auslösen.

CHAR-01 erfasst `dup`, durch `fork` geerbte FDs und weiterhin lesbares `mmap`.
RACE-01 wechselt wiederholt die Ressource hinter derselben FD-Nummer während
Policywechseln. Ein beobachteter falscher Entzug schlägt fehl; ein bestandener
Lauf beweist keine Race-Freiheit. E2E-17 erzeugt einen echten Attach-Fehler durch
einen bereits vorhandenen Tracer, ohne globale ptrace-Schutzregeln zu ändern.

### Revision: atomic publication without debounce

The policy and attribute loaders now act on atomic publication events without a 100-ms
wait. PERF-03 records `publication: atomic-rename-no-debounce`; its timing checks no longer
require a debounce marker. Historical reports retain their original timing records.
Rebuild and rerun PERF-02/PERF-03 on the dedicated Linux target before quoting updated
latencies. Do not reuse the old 100-ms-debounce measurements as current performance.
Local checks: `bash scripts/tests/test-publish-config.sh` and
`PYTHONPATH=scripts/tests/evaluation python3 -B -m unittest discover -s scripts/tests/evaluation -p test_perf03.py`.

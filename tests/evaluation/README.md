# Ergänzende Evaluation

Nur auf dem dedizierten Linux-Testsystem, nach dem Release-Build:

```bash
sudo python3 tests/evaluation/run.py
# Einzelne IDs sind ebenfalls möglich:
sudo python3 tests/evaluation/run.py E2E-11 COMP-04 PERF-02
```

COMP-01 bis COMP-03 laufen als Rust-Komponententests über `./test.sh`.
COMP-04 verwendet echte Maps und benötigt deshalb hier Root.
Die bisherigen zehn E2E-Skripte bleiben über `sudo ./test-e2e.sh` ausführbar.

Jedes zusätzliche Szenario startet eine eigene Runtime mit temporären Dateien.
Vorhandene Runtime-Prozesse oder bekannte gepinnte Maps führen zum Abbruch.
Die Suite entfernt beim Aufräumen nur ihre bekannten Maps und eigenen Prozesse.
Testsuiten dürfen nicht parallel gestartet werden. Die Evaluation verwendet eine
Sperrdatei; das bisherige `test-e2e.sh` kennt diese Sperre nicht.

Alle Artefakte bleiben unter dem ausgegebenen `/tmp/tails-eval-...` erhalten:
`report.json`, Runtime- und Kernel-Logs, Hilfsprozessergebnisse und Fehlerdetails.
Exitstatus 1 bedeutet mindestens einen fehlgeschlagenen Test. Insbesondere
bekannte Produktfehler werden nicht als bestandene Tests behandelt.

Standard: zehn Wiederholungen pro Latenz-/Race-Test, 100 Stabilitätszyklen.
Anpassung z.B. `sudo env EVAL_REPEATS=30 EVAL_STAB_CYCLES=500 python3 tests/evaluation/run.py`.
Die Ausgaben dokumentieren die tatsächlich verwendeten Parameter.

PERF-01 misst 20.000 warme `os.open`-Aufrufe je Zustand, inklusive Python- und
Timeraufwand, ohne `close`. Der Vergleich ist ein sequenzieller Mikrobenchmark,
keine isolierte Messung ausschließlich des Hooks. PERF-02 beobachtet mit 10 ms
Polling die neue Entscheidung. PERF-03 beobachtet EBADF mit 1 ms Polling und
begrenzt den Aktivierungszeitpunkt durch Generationsabfragen; es werden
Latenzintervalle ausgegeben, keine vorgetäuschten exakten Aktivierungszeiten.
Die Rohdaten und Median/p95/p99 werden gespeichert. Bei zehn Wiederholungen
entsprechen hohe Perzentile praktisch dem Maximum und sind nur deskriptiv.

LOAD-01 prüft je 16 statische und Stream-Policies sowie 512 Attribute pro Bank
(1024 Map-Einträge insgesamt für zwei Banken). Der Versuch mit 513 Attributen bei
512 Einträgen in der aktiven Bank soll kontrolliert abgelehnt werden.

CHAR-01 erfasst `dup`, durch `fork` geerbte FDs und weiterhin lesbares `mmap`.
RACE-01 wechselt wiederholt die Ressource hinter derselben FD-Nummer während
Policywechseln. Ein beobachteter falscher Entzug schlägt fehl; ein bestandener
Lauf beweist keine Race-Freiheit. E2E-17 erzeugt einen echten Attach-Fehler durch
einen bereits vorhandenen Tracer, ohne globale ptrace-Schutzregeln zu ändern.

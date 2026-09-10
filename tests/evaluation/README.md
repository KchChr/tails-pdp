# Ergänzende Evaluation

Nur auf dem dedizierten Linux-Testsystem, nach dem Release-Build:

```bash
sudo ./test-evaluation.sh
# Einzelne IDs sind ebenfalls möglich:
sudo ./test-evaluation.sh E2E-11 COMP-04 PERF-02
```

COMP-01 bis COMP-03 laufen als Rust-Komponententests über `./test.sh`.
COMP-04 verwendet echte Maps und benötigt deshalb hier Root.
`sudo ./test-e2e.sh` führt jetzt E2E-01 bis E2E-17 aus. Die ersten zehn
verwenden ihre bisherige gemeinsame Fixture, die sieben neuen jeweils eine
isolierte Runtime. Die zusätzlichen Szenarien sind auch einzeln startbar:

```bash
sudo bash tests/e2e/E2E-12.sh
sudo bash tests/evaluation/LOAD-01.sh
```

## Wo liegt welcher Test?

| Dateien | Inhalt |
|---|---|
| `tests/e2e/E2E-11.sh` bis `E2E-14.sh` | Policy-, Attribut- und Admin-Prüfschritte direkt in Bash |
| `tests/e2e/E2E-15.sh` | UID-Szenario in Bash; `access.py` führt `setresuid` und `open` aus |
| `tests/e2e/E2E-16.sh` | Mehrfachentzug in Bash; `fd_probe.py` hält und beobachtet die FDs |
| `tests/e2e/E2E-17.sh` | Bash-Wrapper für `tests/evaluation/E2E-17.py`; koordiniert zwei Hilfsprozesse und hält den ptrace-Tracer im selben Pythonprozess |
| `tests/evaluation/COMP-04.sh`, `LOAD-01.sh`, `STAB-01.sh` | Admin-, Kapazitäts- und Stabilitätsprüfungen direkt in Bash |
| `tests/evaluation/CHAR-01.sh`, `RACE-01.sh` | Ablauf und Assertions in Bash; FD-/fork-/mmap-Operationen in `fd_probe.py` |
| `tests/evaluation/PERF-01.sh` bis `PERF-03.sh` | Je ein Bash-Wrapper für die gleichnamige Pythondatei; monotone Zeitmessung ohne Shell-Prozessstart pro Messpunkt |

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
Sperrdatei; das bisherige `test-e2e.sh` kennt diese Sperre nicht.

Alle Artefakte bleiben unter dem ausgegebenen `/tmp/tails-eval-...` erhalten:
`report.json`, Runtime- und Kernel-Logs, Hilfsprozessergebnisse und Fehlerdetails.
Exitstatus 1 bedeutet mindestens einen fehlgeschlagenen Test. Insbesondere
bekannte Produktfehler werden nicht als bestandene Tests behandelt.

Standard: zehn Wiederholungen pro Latenz-/Race-Test, 100 Stabilitätszyklen.
Anpassung z.B. `sudo env EVAL_REPEATS=30 EVAL_STAB_CYCLES=500 ./test-evaluation.sh`.
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

# Testbewertung und Evaluation vom 10. September 2026

## Ergebnis und Abgrenzung

Die 18 offenen Testvorschläge aus der Testübersicht sind implementiert. Der Stand
enthält 52 Rust-Tests, die zehn bisherigen E2E-Szenarien und 15 zusätzliche
privilegierte Szenarien. Produktfehler wurden auftragsgemäß **nicht behoben**.
Die beiden Änderungen außerhalb von Testmodulen führen lediglich austauschbare
Speicher-/Lookup-Zugänge ein; Commitreihenfolge, Fehlerweitergabe und
Entscheidungslogik bleiben erhalten.

Die unveränderte Ausgangssuite wurde zuerst auf Commit `5224550` ausgeführt:
46/46 Rust-Tests und 10/10 E2E-Szenarien bestanden, Formatierung und separater
Release-Build ebenfalls. `./test.sh` scheitert nach den erfolgreichen Rust-Tests
an Clippy (`items_after_test_module` in `tails-pdp-userspace-common/src/lib.rs`).
Dieser bestehende Befund wurde nicht durch Abschwächen von `test.sh` verdeckt.

Nach der Erweiterung bestanden 52/52 Rust-Tests. Die beiden geänderten Rust-Crates
wurden zusätzlich separat mit `cargo clippy --locked --package
tails-pdp-attribute-loader --package tails-pdp-userspace-pep --all-targets -- -D
warnings` erfolgreich geprüft. Auch der separate Release-Build war erfolgreich.
Der Clippy-Befund der Gesamtsuite bleibt bestehen.

## Reproduzierbarkeit

Ziel: SSH-Alias `nixrun`, Hostname `nixos`, Linux 6.16.12, x86_64, BPF-LSM aktiv.
Python 3.12.11; Rust-Build in der vorkonfigurierten Nix-Shell. Die Tests liefen mit
Root, die Rust-Tests über den ausdrücklich unprivilegierten Cargo-Runner.
Quelltransfer erfolgte jeweils durch lokalen Commit/Push und `git pull --ff-only`
auf dem Zielsystem. Vorhandene unversionierte Dateien des Zielsystems wurden
nicht verändert; Policies und Attribute der Evaluation liegen in eigenen
Temporärverzeichnissen.

Der maßgebliche zusätzliche Evaluationslauf verwendet Commit `9848f19` und
speichert seine Rohdaten in
[`test-results/2026-09-10/evaluation.json`](test-results/2026-09-10/evaluation.json).
Die Testtreiberkorrektur in diesem Commit betrifft ausschließlich die
Fehlerprotokollierung während eines Runtime-Abbruchs.

Ausführung:

```bash
./test.sh
# Separat erforderlich, weil die bestehende Clippy-Prüfung vorher abbricht:
cargo build --locked --release --bin tails-pdp --bin tails-pdp-admintool
sudo ./test-e2e.sh
sudo python3 tests/evaluation/run.py
```

## Bewertung der bisherigen 46 Rust-Tests

| Bestand | Bewertung | Konkrete Aussagegrenze / Ergänzung |
|---|---|---|
| Gemeinsame Policylogik, 16 Tests | Sinnvolle, deterministische Unit-Tests mit positiven und negativen Fällen für Requestfelder, Entitlements, Operatoren, Typen und Zeitwerte. | Kein geladener Hook und keine realen Attribut-Lookups. Der ursprüngliche Combining-Test prüft Permit gefolgt von Deny, nicht beide Reihenfolgen. E2E-11 ergänzt reale Mehrfachentscheidungen. |
| Policyloader, 14 Tests | Gute Abdeckung von Syntaxfehlern, Bereichsprüfung, rekursivem Einlesen und Aktivierungsreihenfolge. Fehlernachrichten werden geprüft, nicht lediglich irgendein Fehler. | `FakePolicyStore` simuliert einen Bank-Schreibvorgang als Ganzes; keine Teilwrites echter Maps. Kapazität ursprünglich nur oberhalb der statischen Grenze geprüft; LOAD-01 ergänzt Grenzbelegung beider Policyarten. |
| Attributloader, 2 Tests | Brauchbare elementare Parser-Smoke-Tests. | Nur je ein Zahlen-, Boolean- und String-Beispiel sowie wenige Namens-/DEFCON-Fälle. Keine vollständige Verzeichnis- oder Transaktionsprüfung. COMP-01 und COMP-02 schließen diese konkreten Lücken. |
| Triggerkanal, 2 Tests | Präzise Prüfung der begrenzten Kapazität, Koaleszierung und des geschlossenen Empfängers. | Belegt weder Dateiwatcher noch anschließenden Scan. Der nachgelagerte Generationszugriff wird hier nicht geprüft. |
| Userspace-PEP, 12 Tests | Gute isolierte Tests für Identität, Real UID, Deduplizierung und exemplarische Zeitgrenzen. | `FakeFdCloser` macht keinen ptrace-Aufruf. `failed_close_is_attempted_once_without_aborting_scan` versuchte ursprünglich nur denselben FD zweimal; Weiterverarbeitung eines anderen Ziels war trotz Name nicht geprüft. Ein zusätzlicher Test und E2E-17 prüfen dies jetzt. Der 20-ms-Wartetest prüft die Wartefunktion, nicht den vollständigen inaktiven PEP. |

Alle 46 bisherigen Tests bestehen. Das belegt ihre festgelegten Assertions,
nicht automatisch sämtliche Aussagen, die man aus Testnamen ableiten könnte.
Die sechs neuen Rust-Tests prüfen zusätzlichen Kontrollfluss, insbesondere jeden
Ausfallpunkt während einer Attributtransaktion und jede einzelne Bedingung einer
Konjunktion. Sie kopieren nicht lediglich den zu prüfenden Algorithmus.

## Bewertung der bisherigen zehn E2E-Szenarien

| ID | Bewertung |
|---|---|
| E2E-01 | Relevanter Systemnachweis: Verifier/Attach, Startmeldung und Maps. Keine Langzeitgarantie. |
| E2E-02 | Sinnvolle Kontrolle des Default-Allow-Verhaltens in der vom Runner hergestellten Ausgangslage. |
| E2E-03 | Gute Prüfung des vollständigen Hinzufügen-/Entfernen-Zyklus einer statischen Deny-Policy. |
| E2E-04 | Prüft die aktuelle UTC-Stunde. Ein Stundenwechsel zwischen Zeitaufnahme und Aktivierung kann einen umgebungsbedingten Fehlschlag erzeugen; kein Test des tatsächlichen Übergangs. |
| E2E-05 | Aussagekräftiger Allow–Deny–Allow-Zyklus für das Systemattribut, einschließlich Aktivierung der Ausgangspolicy. |
| E2E-06 | Analog für Subject-Attribute, inklusive erfolgreicher Ausgangsaktivierung. Bisher nur identische Real/Effective UID; E2E-15 ergänzt unterschiedliche UIDs. |
| E2E-07 | Analog für Resource-Attribute mit realer Device-/Inode-Zuordnung. E2E-12 ergänzt die gemeinsame Konjunktion. |
| E2E-08 | Guter Verhaltensnachweis für syntaktisch ungültige Policies. Prüft Logmeldung und weiterhin wirksames Deny; die unveränderte Generationsnummer wird nicht direkt verglichen. |
| E2E-09 | Starker selektiver Entzugsnachweis mit echten FDs und konkretem EBADF. Bisher nur ein verletzender und ein erlaubter FD; E2E-16, E2E-17 und CHAR-01 erweitern die Aussage. |
| E2E-10 | Sinnvolle Inhaltsprüfung der Admin-Ausgabe mit Vergleich der Generationen vor/nach erneutem Lesen. COMP-04 ergänzt die weiteren Unterbefehle. |

Gemeinsame Einschränkungen des bisherigen Shell-Runners:

- `wait_for_access deny` akzeptiert jeden fehlgeschlagenen `cat`-Aufruf als Deny.
  Dadurch könnten etwa ein fehlender Pfad oder ein anderer I/O-Fehler einen
  irreführenden Erfolg erzeugen. Der neue Python-Treiber akzeptiert ausschließlich
  `EPERM` als LSM-Deny und lässt andere Fehler fehlschlagen.
- `wait_for_log` durchsucht das gesamte bisherige Log. Die Muster sind im
  derzeitigen Einmaldurchlauf weitgehend eindeutig, bei Wiederholungen könnten
  alte Meldungen genügen. Neue Update-Tests lesen nur den neuen Logabschnitt.
- Die alten Szenarien teilen einen Runtime-Zustand, brechen beim ersten Fehler ab
  und löschen bei Erfolg ihre Artefakte. Neue Szenarien starten einzeln, behalten
  die Ergebnisse und setzen die Suite nach einem Szenariofehler fort.
- `pgrep` schützt nicht atomar gegen parallele Starts; außerdem entfernt der alte
  Runner bestehende Pins. Die zusätzliche Suite verweigert bestehende bekannte
  Pins und sperrt andere Instanzen ihres eigenen Runners. Beide Runner dürfen
  weiterhin nicht gleichzeitig gestartet werden.

Diese Testgrenzen bleiben dokumentiert; die bisherigen Assertions wurden nicht
nachträglich so geändert, dass ihr ursprünglicher erfolgreicher Lauf eine stärkere
Aussage vortäuscht.

## Neue Funktions- und Grenzfallnachweise

COMP-01 bis COMP-03 bestehen als Komponententests. COMP-04 und E2E-11 bis E2E-17
bestehen auf dem Zielkernel. E2E-14 weist die einzige aktive Deny-Policy samt
Ressourcen-Inode, Bedingung und tatsächlichem Attributwert in der Admin-Ausgabe
nach. Das ist eine Zustandsrekonstruktion, kein individuelles Auditlog jeder
Dateiöffnung und keine Anzeige des ursprünglichen Policynamens.

CHAR-01: Im Eltern- und Kindprozess wurden jeweils alle vier betroffenen FDs
(einschließlich `dup` und `fork`-Vererbung) geschlossen. Je zwei erlaubte FDs blieben
offen. In beiden Prozessen blieb `mmap` lesbar. Ein FD-Entzug widerruft also den
bereits aufgebauten Speicherzugriff nicht.

RACE-01: Zehn Policyzyklen, 2535 Wechsel der Ressource hinter derselben FD-Nummer,
kein beobachteter falscher Entzug eines sicheren FDs. Das ist ein begrenzter
Stresstest. Die Lücke zwischen Identitätsaufnahme und späterem ptrace-Entzug bleibt
bestehen; ein erfolgreicher Lauf ist kein Nachweis der Race-Freiheit.

## Nachgewiesener Produktfehler: Attributkapazität

LOAD-01 **schlägt fehl**. Je 16 statische und 16 Stream-Policies werden akzeptiert;
der jeweils 17. Eintrag wird ohne Generationswechsel abgelehnt. Drei gültige
Attributwechsel mit je 512 Einträgen gelingen ebenfalls.

Bei anschließend 513 Attributen in der neuen Bank und weiterhin 512 in der aktiven
Bank würde die gemeinsame Map mit maximal 1024 Einträgen überschritten. Der
Map-Schreibaufruf scheitert mit `os error 7` (`Argument list too long`). Die aktive
Generationsnummer bleibt zwar erhalten, die Runtime beendet sich aber mit Status 1.
Damit ist die Anforderung einer kontrollierten Ablehnung bei weiter funktionsfähiger
Runtime nicht erfüllt. Nach dem Runtime-Ende bleibt auch kein regulärer
Enforcement-Betrieb erhalten.

Ursache im Quellcode: `apply_attribute_directory` reicht einen Fehler aus
`commit_attributes` mit `?` weiter; `run_attribute_updater` und das zentrale
`tokio::select!` reichen ihn bis zum Programmende durch. Die isolierten
COMP-02-Tests bestehen trotzdem zu Recht: Sie prüfen die transaktionale
Generationssichtbarkeit, nicht das Weiterlaufen der gesamten Runtime.

Der erste Lastlauf zeigte außerdem kurzzeitig `EPERM` beim Öffnen von
Diagnosedateien während des Runtime-Abbaus. Der Testtreiber schreibt Fehlerberichte
nun nach dem Aufräumen und wartet bei diesem Lastfall zunächst auf das Prozessende.
Diese Beobachtung wird nicht als isoliert nachgewiesene weitere Fehlerursache
gewertet.

## Quantitative Messungen

Alle Zahlen beziehen sich auf diesen Host und diesen Lauf; keine verbindlichen
Performancegrenzen wurden vorgegeben. PASS bedeutet hier erfolgreiche Messung und
funktional beobachteter Zustandswechsel, nicht das Einhalten eines erfundenen SLA.

| Messung | Stichprobe | Median | p95 |
|---|---:|---:|---:|
| Dateiöffnung ohne Runtime | 20.000 | 3,845 µs | 4,024 µs |
| Dateiöffnung mit Runtime und leerem Policystand | 20.000 | 4,389 µs | 4,621 µs |
| Dateiöffnung mit passender Permit-Policy | 20.000 | 4,412 µs | 6,629 µs |
| Policydateiänderung bis neues Deny | 10 | 102,41 ms | 103,51 ms |
| Attributdateiänderung bis neues Deny | 10 | 103,34 ms | 114,12 ms |
| Policydateiänderung bis EBADF aller drei Ziel-FDs | 10 | 58,91 ms | 110,65 ms |

Der gemessene mediane Öffnungsaufwand steigt gegenüber der Baseline um ca. 14,1 %
bei leerem Policystand und 14,7 % mit passender Permit-Policy. Gemessen wird ein
warmer `os.open` einschließlich Python-/Timeraufwand; `close` liegt außerhalb des
Zeitfensters. Es handelt sich nicht um den isolierten Aufwand des LSM-Hooks.

PERF-02 verwendet ein 10-ms-Pollingintervall. PERF-03 prüft FDs mit 1-ms-Polling und
begrenzt die Aktivierungszeit durch aufeinanderfolgende Generationsabfragen.
Die zehn Intervalle für Aktivierung bis beobachtetem EBADF liegen mit ihren
unteren Grenzen zwischen 7,02 und 8,45 ms und ihren oberen Grenzen zwischen 9,34
und 10,84 ms. Die einzelnen Intervallpaare stehen im JSON; daraus wird keine
scheinexakte einzelne Aktivierungslatenz abgeleitet. Generationsabfragen und
Hilfsprozessmessung verursachen selbst Aufwand. Bei zehn Wiederholungen sind p95
und p99 das beobachtete Maximum, keine belastbare Tail-Latenzschätzung.

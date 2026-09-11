# Review Kapitel 6 – Evaluation

Stand: 11.09.2026. Begutachtet: aktueller Arbeitsbaum und vorhandene PDF, S. 56–69. Seitenangaben beziehen sich auf die gedruckten Seitenzahlen der 75-seitigen PDF. F-IDs sind reviewweit eindeutig; Querverweise bezeichnen denselben Befund und keine zusätzlichen Mängel.

## 1. Aufgabe des Kapitels

Die Evaluation muss aus den Anforderungen abgeleitete Funktionen, Fehlerfälle und Grenzen prüfen sowie quantitative Charakterisierung von allgemeinen Garantien unterscheiden. Evidenz muss einem eindeutigen Quell- und Umgebungsstand zugeordnet sein.

## 2. Gesamteindruck

**solide, aber überarbeitungsbedürftig.** Für eine Bachelorarbeit liegt eine überdurchschnittlich breite funktionale Testbasis vor. Die Zahlen sind nachrechenbar und negative Ergebnisse werden offen berichtet. Abschließende Schwächen betreffen die pauschale FA-Erfüllung, zwei dynamische FD-Trigger, den finalen Nachweisstand und die Messphasen.

## 3. Stärken

- 59 Rust-Tests sind sowohl im aktuellen Quellcode als auch in den archivierten Ergebniszeilen nachvollziehbar.
- Die 17 E2E-Szenarien decken erlaubte/verweigerte Opens, Namespaces, Combining, Real UID, selektiven FD-Entzug und Attach-Konflikte ab.
- Der Kapazitätsfehler wird nicht versteckt: frühere LOAD-01-Niederlage, Korrektur und erfolgreiche Nachtests sind archiviert.
- mmap-Weiterlesbarkeit und stochastische Race-Testgrenzen werden offen eingeordnet.
- Messung inklusive Python-/Timeraufwand, Polling, kleiner Stichprobe und p95=Maximum bei n=10 wird bereits transparent relativiert.
- Alle sechs berichteten Mediane und p95-Werte wurden aus den Samples korrekt nachgerechnet.

## 4. Kritikpunkte

### F07 – Kritikpunkt: Zeitgrenzen und Attributänderungen beim FD-Entzug nicht vollständig Ende-zu-Ende belegt

**Fundstelle:** §6.2.2–6.3.4, S.59–69; tests/e2e/E2E-04.sh:10; E2E-09.sh:70; tests/evaluation/PERF-03.py:10; pep.rs:304.

**Priorität:** P1.

**Kategorie:** Evaluation; Forschungsfrage.

**Problem:** Zeitlogik und Trigger werden isoliert getestet. E2E-04 installiert eine zur aktuellen Stunde passende Policy für neue Opens. Die nachgewiesenen FD-Entzüge werden durch Policydateiänderungen ausgelöst. Ein bestehender FD, der allein durch Ablauf einer Zeitgrenze unzulässig wird, sowie ein allein durch Attributaktivierung ausgelöster realer Entzug sind in den untersuchten Szenarien nicht eigens belegt.

**Warum ist das problematisch?** Gerade diese beiden Trigger gehören zur Zielsetzung und zur Antwort der Forschungsfrage. Gemeinsame Auswertung und Unit-Tests machen das Verhalten plausibel, ersetzen aber die Integration von Timer, Map-Zeit und ptrace nicht.

**Auswirkungen:** Partielle Evidenzlücke im ASBAC-Kern; kein Beweis, dass die Funktion fehlschlägt.

**Lösung A – empfohlen:** Zwei kleine reale Szenarien auf dem Zielsystem ergänzen: Policy und Attributdateien unverändert lassen und eine Zeitgrenze überschreiten; separat nur ein relevantes Attribut ändern. Jeweils verletzenden und weiterhin zulässigen FD sowie Generation/Zeit beobachten.

**Lösung B – Alternative:** Falls keine Testzeit bleibt, die beiden Pfade als durch Komponenten-/Codeanalyse gestützt, aber nicht vollständig E2E untersucht kennzeichnen und die Gesamtbehauptung entsprechend eingrenzen.

**Empfehlung des Gutachters:** A bietet hohen Nutzen bei überschaubarem Aufwand; B ist wissenschaftlich ehrlich.

**Aufwand:** hoch: 2–8 Stunden einschließlich Zielsystemlauf.

**Erwarteter Nutzen:** hoch.

**Relevanz für die Benotung:** mittel bis hoch: stärkt unmittelbar den Nachweis dynamischer Nachkontrolle.

### F08 – Kritikpunkt: Abgabestand und Nachweisstand sind nicht abschließend geschlossen

**Fundstelle:** §6.1, S.56–58; §6.3, S.64–65; §7.2, S.71; 06-evaluation.tex:68,361,380; aktueller HEAD 756af74 plus vorhandene Arbeitsbaumänderungen.

**Priorität:** P1.

**Kategorie:** Reproduzierbarkeit; Thesis-vs.-Code.

**Problem:** Die Thesis unterscheidet 9848f19 und 35e1d2b bereits transparent. Der aktuelle Code enthält zusätzlich die Umordnung in userspace-common, die den dokumentierten Clippy-Befund items_after_test_module beseitigt. Ein erfolgreicher Gesamtlauf der aktuellen zentralen Prüfkette ist damit jedoch noch nicht belegt. Die Ergebnis-JSONs dokumentieren Kernel, Python, Commit und Parameter, aber nicht die angekündigten vollständigen NixOS-/Nixpkgs-/Rust-/Cargo-/Hypervisor-Nachweise. Ein separater VM-Konfigurationsexport wurde in den untersuchten Abgabeartefakten nicht gefunden.

**Warum ist das problematisch?** Ein historisch korrekt berichteter Fehler ist kein aktueller Codefehler. Umgekehrt ist eine offensichtliche Korrektur kein Nachweis für einen grünen finalen Lauf. Ohne Nixpkgs-Revision bleibt die Umgebung trotz shell.nix veränderlich.

**Auswirkungen:** Die Einreichung ist schlechter reproduzierbar als OA-04 „erfüllt“ nahelegt; der behauptete offene Clippy-Mangel ist veraltet.

**Lösung A – empfohlen:** Abgabestand eindeutig einfrieren, gesamte Prüfkette auf Linux ausführen und Ergebnis/Exitcode/Commit/Dirty-Status archivieren. Tatsächliche Toolchain- und Systemversionen sowie VM-Konfiguration ergänzen; alte Messstände erhalten und eine Ergebnis-zu-Artefakt-Tabelle angeben.

**Lösung B – Alternative:** Ohne neuen Lauf die bestehende Evidenz exakt historischen Ständen zuordnen, Clippy als inzwischen strukturell korrigiert, aber final nicht neu nachgewiesen darstellen und OA-04 nur teilweise erfüllt bewerten.

**Empfehlung des Gutachters:** A ist der passende Abschluss einer Abgabefassung. B ist besser als eine unbelegte Erfolgsmeldung.

**Aufwand:** hoch: 2–8 Stunden mit verfügbarem Zielsystem.

**Erwarteter Nutzen:** sehr hoch.

**Relevanz für die Benotung:** hoch: Nachvollziehbarkeit und endgültiger Qualitätsnachweis.

### F09 – Kritikpunkt: 58,91 ms Entzugslatenz benötigt Erklärung der Ereignisphase

**Fundstelle:** §6.3.3, S.68; §4.3.2; tests/evaluation/PERF-03.py:9; support.py:31,137; policy_source.rs:153.

**Priorität:** P2.

**Kategorie:** Messmethodik; Interpretation.

**Problem:** Der Median liegt unter der beschriebenen 100-ms-Bündelungsverzögerung. Das ist nicht automatisch ein Messfehler: Der Timer beginnt nach dem Schreiben der temporären Datei unmittelbar vor replace; außerdem können Restereignisse vorheriger Änderungen den bereits laufenden 100-ms-Warteabschnitt gestartet haben. Der Loader drainiert die Ereignisse nicht zu einer garantierten Ruhephase. Die Messung charakterisiert dadurch die konkrete Updatefolge, nicht notwendigerweise ein isoliertes Ereignis aus ruhendem Zustand.

**Warum ist das problematisch?** Ohne Erklärung wirken Reaktions- und Entzugswerte widersprüchlich. Eine ereignisgetriebene Architektur muss Messstart und Ereignisphase präzise definieren.

**Auswirkungen:** Begrenzt die Vergleichbarkeit der Latenzen; die Rohwerte selbst sind rechnerisch korrekt.

**Lösung A – empfohlen:** Messstart exakt benennen und Phaseneffekt diskutieren; für eine belastbare isolierte Kennzahl vor jedem Durchlauf einen nachgewiesen ruhenden Watcher-/Scan-Zustand herstellen und neu messen.

**Lösung B – Alternative:** Werte unverändert als Charakterisierung der vorhandenen Updatefolge belassen; keine Mindestlatenz oder allgemeine Überlegenheit des FD-Pfades daraus ableiten.

**Empfehlung des Gutachters:** A, sofern Zielsystemzeit vorhanden; sonst B mit klarer Erklärung. Die Ursache ist aus dem Ablauf plausibel hergeleitet, mangels Zeitstempel jedes inotify-Ereignisses nicht experimentell eindeutig isoliert.

**Aufwand:** mittel: 30 Minuten bis 2 Stunden für Erklärung; hoch für Neumessung.

**Erwarteter Nutzen:** hoch.

**Relevanz für die Benotung:** mittel: verhindert eine naheliegende methodische Rückfrage.

### F10 – Kritikpunkt: Viele Opens ersetzen keine unabhängigen Messläufe

**Fundstelle:** §6.3.3, S.68; tests/evaluation/PERF-01.py:7; thesis/test-results/2026-09-10/bash/summary.json.

**Priorität:** P2.

**Kategorie:** Performance; externe/interne Validität.

**Problem:** PERF-01 misst je 20.000 Opens in einer festen Reihenfolge Baseline → leere Runtime → Permit. Diese Aufrufe sind keine 20.000 unabhängigen Versuchsläufe. Der ebenfalls archivierte Bash-Lauf liefert 3,295/4,023/3,908 µs und ungefähr 22,1/18,6 % statt 14,1/14,7 %. Das widerlegt den berichteten Lauf nicht, zeigt aber relevante Zwischenlaufvariation. Dynamische Stream-Policies und maximale Policybelegung werden nicht als Performancefälle gegenübergestellt.

**Warum ist das problematisch?** Cache-/Scheduler-/Hosteffekte sind bei einem kleinen absoluten Unterschied relevant; Reihenfolge und Laufstreuung können den relativen Effekt beeinflussen.

**Auswirkungen:** Der Mehraufwand ist als Beobachtung eines Laufs solide, als typische Größenordnung nur begrenzt abgesichert. Die Thesis zieht erfreulicherweise keine allgemeine Geschwindigkeitsgarantie.

**Lösung A – empfohlen:** Vorhandenen zweiten Lauf knapp gegenüberstellen, Auswahl des berichteten Laufs erklären und mehrere unabhängige, wechselnd angeordnete Blöcke sowie mindestens einen Stream-Fall messen.

**Lösung B – Alternative:** Die jetzigen Zahlen ausdrücklich als Einzellaufcharakterisierung stehenlassen und fehlende unabhängige Wiederholungen sowie Stream-/Lastmessungen als Grenze nennen.

**Empfehlung des Gutachters:** A verbessert die Evidenz; B genügt bei engem Machbarkeitsanspruch. Keine Pflicht zu einem umfassenden MAC-Benchmark.

**Aufwand:** hoch: 2–8 Stunden für A; gering für B.

**Erwarteter Nutzen:** mittel.

**Relevanz für die Benotung:** mittel: begrenzt eher eine sehr gute als eine ausreichende Bewertung.


**Kapitelübergreifende Befunde:** F02 ist für §6.3.4 zwingend relevant: FA-06 ist nach seinem Wortlaut nur teilweise erfüllt. F15 betrifft OA-03; F04 begrenzt, was die Generationstests nachweisen. Keine dieser Einschränkungen löscht die tatsächlich bestandenen Tests.

## 5. Fehlende Inhalte

Eine einzige Tabelle Anforderung → Test-ID → Artefakt/Commit → Aussagegrenze würde die Resultate besser verbinden. Die Charakterisierungs-, Race-, Last- und Performancefälle sollten schon im Versuchsdesign vor den Ergebnissen mit Messstart/-ende und Bestehenskriterium eingeführt werden. 100 Zyklen sind hier ein kurzer Stabilitätstest, kein Dauertest; die Thesis sagt dies bereits.

## 6. Überflüssige oder redundante Inhalte

Einige VM-/NixOS-Erklärungen nehmen mehr Raum ein als die eigentlichen Performanceprotokolle. Details zu EFI/UUIDs sind weniger relevant als tatsächliche Toolchainrevision, physische Host-CPU und unabhängige Messwiederholungen.

## 7. Quellen und Belege

Eigene Messungen benötigen Rohdaten, kein Literaturzitat. Die vorhandenen Konfigurationsdateien und Logs wurden lesend geprüft. Exakte Softwareversionen werden nicht erfunden; nicht aufgefundene Metadaten sind als fehlender Nachweis markiert. Im Review wurden keine Linux-Tests erneut ausgeführt.

## 8. Bezug zum Quellcode

PERF-01/02/03, fd_probe, RACE-01, E2E-04/09/17, Runner und Produktionspfade wurden gegengeprüft. Die 59 Tests sind lokale Logik-/Komponentenevidenz, nicht 59 Verifier-/Kerneltests. Die abschließenden E2E-11–17- und LOAD/STAB-Reports nennen 35e1d2b. Die stärkere Behauptung einer aktuell grünen Gesamtkette folgt daraus nicht.

## 9. Beitrag zur Forschungsfrage

Die Machbarkeit ist für die gezeigten Konfigurationen empirisch gut gestützt. Allgemeine Sicherheit, unmittelbarer garantierter Entzug und umfassende Skalierbarkeit werden weder benötigt noch nachgewiesen. Die dynamische Nachkontrolle ist insgesamt nur teilweise vollständig integriert getestet.

## 10. Wichtigste Maßnahmen

1. FA-06-Ergebnis korrigieren (F02).
2. Abgabestand, Toolchain und vollständigen Runnerabschluss nachweisen (F08).
3. Zeitgrenzen- und Attributtrigger beim realen FD-Entzug ergänzen oder Evidenzgrenze ausweisen (F07).
4. 58,91-ms-Messung über Ereignisphase erklären (F09).
5. Zweiten vorhandenen Lauf und unabhängige Wiederholungen berücksichtigen (F10).


# Nachprüfung der Evaluation ohne Debounce

Ausgewertet wurden die bereitgestellten Dateien unter `thesis/test-results-2/`.
Die ursprünglichen Nachweise unter `thesis/test-results/final-evaluation/` bleiben unverändert.

## Zuordnung und Prüfumfang

- Beide neuen Reports nennen Commit `3460104b59bb093b461f93b3ccd58c2540e0d7d9`, Linux 6.16.12 und x86_64; der Commit entspricht dem lokalen HEAD bei dieser Auswertung.
- `tails-eval-oma1c72v/report.json`: E2E-11 bis E2E-19 jeweils PASS.
- `tails-eval-iy7a07nk/report.json`: COMP-04, CHAR-01, RACE-01, PERF-01, PERF-02, PERF-03, LOAD-01 und STAB-01 jeweils PASS.
- PERF-03 trägt die Kennzeichnung `atomic-rename-no-debounce`.
- Die Kennzahlen aller sechs Messreihen wurden aus `samples` nachgerechnet: Anzahl, Median, p95 nach der implementierten Nearest-Rank-Berechnung, Minimum und Maximum stimmen mit den Reports überein.
- Die drei separaten PERF-Detaildateien stimmen mit ihren eingebetteten Reportdaten überein.
- Alle zehn PERF-03-Phasen wurden gegen das Runtime-Log und die aktuelle `phase_timestamps`-Prüfung abgeglichen. Reihenfolge, jeweils eine passende Aktivierung, Generationenwechsel, Gesamtdauer und Grenzen der Aktivierung-bis-Entzug-Intervalle sind konsistent. In allen Proben sind die drei betroffenen FDs geschlossen und die zwei sicheren FDs weiterhin geöffnet.

Die Reports erfassen einen Commit, aber keinen Dirty-Status oder Binary-Hash. Die Zuordnung stützt sich daher zusätzlich auf das protokollierte Verfahren und die konsistenten Phasen. Die übergebenen Dateien enthalten keinen vollständigen neuen Konsolenmitschnitt der Unit-, Build- und Qualitätsprüfkette. Die bisherigen 61 Rust-Tests und vollständigen 19 E2E-Szenarien bleiben in der Thesis ausdrücklich dem ursprünglichen Nachweisstand zugeordnet; für die neue Version werden die tatsächlich vorliegenden Szenarioreports genannt.

## Nachgerechnete Zeiten

| Messreihe | n | Median | p95 | Minimum | Maximum |
| --- | ---: | ---: | ---: | ---: | ---: |
| Dateiöffnung ohne Runtime | 20.000 | 4,347 µs | 4,846 µs | 4,122 µs | 53,077 µs |
| Runtime ohne Policy | 20.000 | 4,552 µs | 6,639 µs | 4,311 µs | 36,204 µs |
| Passende Permit-Policy | 20.000 | 4,534 µs | 5,264 µs | 4,329 µs | 126,755 µs |
| Policyänderung bis Deny | 10 | 10,415 ms | 10,438 ms | 10,332 ms | 10,438 ms |
| Attributänderung bis Deny | 10 | 10,549 ms | 10,625 ms | 0,323 ms | 10,625 ms |
| Policyänderung bis beobachtetes EBADF | 10 | 9,145 ms | 13,966 ms | 8,703 ms | 13,966 ms |

Gegenüber der neuen Baseline beträgt der mediane Mehraufwand:

- Runtime ohne Policy: 0,205 µs beziehungsweise 4,716 %.
- Permit-Policy: 0,187 µs beziehungsweise 4,302 %.

Die p95-Differenzen zur Baseline betragen 1,793 µs beziehungsweise 37,000 % ohne Policy sowie 0,418 µs beziehungsweise 8,626 % mit Permit-Policy. Unterschiede zwischen den sequenziell gemessenen Zuständen sind keine Belege eines Leistungsvorteils der Permit-Auswertung. PERF-01 misst `os.open` einschließlich Python- und Timeraufwand bei warmem Cache; `close` liegt außerhalb des Messintervalls.

## Interpretation der Änderungs- und Entzugslatenz

PERF-02 prüft den tatsächlichen Zugriffszustand mit einem Beobachtungsabstand von 10 ms. Die Mediane liegen nahe diesem Abstand. Ein schneller Zustandswechsel unmittelbar nach einer erfolglosen Prüfung wird erst bei der nächsten Prüfung beobachtet. Die Attributmessreihe enthält einen Wert von 0,323 ms und neun Werte um 10 ms. Deshalb die Werte als **Zeit bis zur beobachteten Entscheidung**, einschließlich Polling, und nicht als präzise interne Aktivierungszeit berichten. Eine feste Pollingdauer ist auch keine feste obere Fehlergrenze, da Scheduling hinzukommt.

PERF-03 beginnt vor dem abschließenden Rename einer außerhalb des überwachten Baums vorbereiteten Datei. Vor Messbeginn wurde der ruhende Watcher mit abgeschlossenen Scans über 300 ms geprüft. Die FD-Probe beobachtet EBADF mit 1 ms Polling.

- Veröffentlichung bis Ereignisempfang: Minimum 0,174 ms, Median 0,250 ms, Maximum 0,295 ms.
- Veröffentlichung bis Aktivierungsbeginn: Minimum 0,313 ms, Median 0,468 ms, Maximum 5,201 ms.
- Veröffentlichung bis Aktivierungsende: Minimum 0,323 ms, Median 0,481 ms, Maximum 5,227 ms.
- Die unteren Aktivierung-bis-EBADF-Grenzen liegen zwischen 8,195 und 10,004 ms; die oberen zwischen 8,220 und 10,016 ms.

Die Aktivierungsmarkierungen umschließen den Map-Systemaufruf und ergeben ein Intervall. Die Messung enthält Instrumentierung, Scheduling, FD-Nachbewertung und Beobachtung. Die längere Gesamtdauer einer Wiederholung ist mit einem verzögerten Aktivierungsbeginn vereinbar; die Ursache der Verzögerung wird aus den Zeitmarkierungen allein nicht bewiesen.

Der alte PERF-03-Median betrug 110,435 ms, der neue 9,145 ms. Das ist mit dem Wegfall der bewussten 100-ms-Wartephase vereinbar. Es ist kein kontrollierter A/B-Versuch, der sämtliche anderen Einflüsse ausschließt. Besonders die geänderte PERF-01-Baseline zeigt, dass die Läufe nicht hinsichtlich aller Laufzeitbedingungen identisch sind.

Bei zehn Latenzwiederholungen ist p95 bereits das Maximum. Die Werte beschreiben den vorliegenden Lauf, liefern aber keine belastbare Schätzung seltener Ausreißer und keine Echtzeitgarantie. Für eine genauere Charakterisierung empfiehlt sich ein separater Lauf mit mindestens 100 Wiederholungen; eine verbesserte PERF-02-Auflösung wäre als eigene Methodenänderung zu dokumentieren.

## Übernahme in die Thesis

Kapitel 6 enthält die neuen Messwerte, Quellenpfade, absolute und relative Mehrkosten sowie die Einschränkungen durch Polling und geringe Wiederholungszahl. Kapitel 7 fasst dieselben Ergebnisse zusammen. Der ursprüngliche Datenbestand und die neuen Rohdaten wurden nicht verändert. Das vorhandene doppelte Caption-/Label-Paar der Performance-Tabelle wurde bei der Überarbeitung entfernt.

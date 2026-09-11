# Prüfprotokoll des Abschlussreviews

Stand: 11.09.2026. Dieses Protokoll dokumentiert den Umfang und die Grenzen der Begutachtung; es ist kein neuer Testnachweis für den Prototyp.

## Gelesener und analysierter Umfang

- Alle sieben Kapitel in `thesis/sections/` vollständig gelesen; Gesamtargumentation vor der Codeanalyse rekonstruiert.
- Vorhandene 75-seitige Abgabe-PDF einschließlich Titel, Inhalts- und Literaturverzeichnis einbezogen; Text und Abbildungsreferenzen abgeglichen. Der Platzhalter auf PDF-Seite 39 wurde zusätzlich visuell am gerenderten PDF geprüft. Keine vollständige pixelweise Satzkontrolle jeder Seite behauptet.
- Architektur und relevante Produktionspfade der acht Crates, Tests und Laufartefakte gemäß [Code-Audit](Code_Thesis_Audit.md) analysiert.
- Alle 36 zitierten Literaturkeys im [Quellen-Audit](Quellen_Audit.md) erfasst. Fachliche Deckung anhand tatsächlich gelesener Passagen; unvollständige Abrufe ausdrücklich gekennzeichnet.
- Forschungsfrage, Anforderungen, Entwurfsentscheidungen, Umsetzung, Ergebnisinterpretation und Fazit kapitelübergreifend verglichen.
- Security, TCB, Fehler-/Ausfallpfade, Reference-Monitor-Kriterien, ptrace-Grenzen, Messvalidität und Abbildungen berücksichtigt.

## Prüfung der archivierten Evaluation

Die berichteten Mediane und p95-Werte wurden aus `thesis/test-results/2026-09-10/evaluation.json` nachgerechnet. 20.000 Samples pro PERF-01-Zustand sowie je zehn Messungen in PERF-02/03 sind archiviert. Die sechs Median-/p95-Paare stimmen mit den gerundeten Thesiswerten überein.

| Fall | Median | p95 |
|---|---:|---:|
| PERF-01 Baseline | 3.845 ns | 4.024 ns |
| PERF-01 leere Runtime | 4.389 ns | 4.621 ns |
| PERF-01 Permit | 4.412 ns | 6.629 ns |
| PERF-02 Policy | 102,4075 ms | 103,5107 ms |
| PERF-02 Attribut | 103,3351 ms | 114,1201 ms |
| PERF-03 FD-Entzug | 58,9132 ms | 110,6501 ms |

Punkte in den ns-Werten sind Tausendertrennzeichen. Relativer Medianmehraufwand: rund 14,15 % bzw. 14,75 %. Historischer LOAD-01-Fehler und spätere erfolgreiche Kapazitäts-/Stabilitätsnachtests wurden unterschieden. Der archivierte alternative Bash-Lauf wurde wegen der abweichenden Performancewerte ergänzend berücksichtigt.

Die 59 Rust-Testresultate, E2E-Protokolle und CHAR-/RACE-/STAB-Nachweise wurden als vorhandene Evidenz bewertet. Der Bericht behauptet keine eigene Wiederholung. Die in der Thesis genannte Laufdauer von rund 178 Sekunden des finalen Stabilitätstests wurde nicht unabhängig aus einer eindeutigen maschinenlesbaren Dauerangabe bestätigt; dessen PASS-Status und Parameter sind belegt. Hieraus wird kein Widerspruch konstruiert.

Nicht durchgeführt: Linux-Build, Verifierlauf, privilegierte E2E-Tests, Zugriff auf das dedizierte Zielsystem oder neue Benchmarkmessung. Grund: lokales macOS-Ziel und ausdrückliches Änderungsverbot außerhalb von Review.

## Vollständigkeitskontrolle

Sieben Kapitelreviews mit jeweils zehn nummerierten Abschnitten sind vorhanden. Die 16 F-Befunde enthalten konkrete Fundstellen, Prioritäten, Begründungen, Lösungen, Empfehlung und Aufwand-/Nutzen-/Notenabschätzung; zwei ergänzende C-Befunde stehen im Code-Audit. Wiederholte IDs sind Querverweise auf denselben Befund und erhöhen dessen Gewicht nicht künstlich.

Die Gesamtbewertung wird nach den Kapitelreviews und beiden Audits erstellt und umfasst die 15 angeforderten Abschnitte, ein eindeutiges Urteil zur Abgabereife, eine Note mit Korridor und einen konkreten Maßnahmenplan. Beleglücken, plausible Risiken und tatsächlich festgestellte Widersprüche werden getrennt behandelt.

## Änderungsgrenze und Versionskontrolle

Vor Beginn lagen bereits Änderungen an README, Testskripten, Testdokumentation, drei Thesis-Kapiteln und LaTeX/PDF-Artefakten sowie zwei unversionierte Test-Runner vor. Diese wurden weder korrigiert noch zurückgesetzt.

Der abschließende Git-Status wurde gegen diese zu Beginn erfasste Dateiliste verglichen: **identisch außerhalb von Review/**. Diese Kontrolle prüft den Versionskontrollstatus; sie wird nicht als lückenloser byteweiser Vorher-nachher-Vergleich aller ignorierten Dateien ausgegeben. Sämtliche schreibenden Aktionen des Reviews erzeugen ausschließlich Markdown-Dateien im Root-Verzeichnis `Review/`; weder Build noch Tests noch PDF-Export wurden ausgeführt. Die ältere Sammlung `thesis/Review/` bleibt unberührt.

Die abschließende automatisierte Dokumentprüfung war erfolgreich: elf Markdown-Dateien, sieben Kapitel mit jeweils zehn Abschnitten, Gesamtbewertung mit 15 Abschnitten, vollständige Pflichtfelder der F-Befunde und gültige lokale Markdown-Verweise. Der Vergleich der aus den Thesis-Kapiteln extrahierten 36 Zitationskeys mit dem Quellen-Audit ergab keine fehlenden Einträge. Die Gesamtbewertung wurde erst nach den Einzelreviews und beiden Audits erstellt.

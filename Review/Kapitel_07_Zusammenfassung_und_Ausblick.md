# Review Kapitel 7 – Zusammenfassung und Ausblick

Stand: 11.09.2026. Begutachtet: aktueller Arbeitsbaum und vorhandene PDF, S. 70–72. Seitenangaben beziehen sich auf die gedruckten Seitenzahlen der 75-seitigen PDF. F-IDs sind reviewweit eindeutig; Querverweise bezeichnen denselben Befund und keine zusätzlichen Mängel.

## 1. Aufgabe des Kapitels

Das Abschlusskapitel muss die Forschungsfrage ausdrücklich beantworten, Antwort und Evidenz verbinden sowie Implementierungsgrenzen, Ansatzgrenzen und zukünftige Arbeiten unterscheiden.

## 2. Gesamteindruck

**gut.** Die Forschungsfrage wird tatsächlich beantwortet. Es gibt ein klares Ergebnis und eine fachlich sinnvolle Begrenzung. Das Kapitel ist deutlich stärker als ein bloßes Feature-Fazit, übernimmt aber einzelne Evidenz- und Konsistenzlücken der vorangehenden Kapitel.

## 3. Stärken

- Explizite Antwort: hybride Architektur ermöglicht ausgewählte ASBAC-Prinzipien für file_open.
- Keine Gleichsetzung des Prototyps mit vollständigem SAPL/PDP oder einem vollständigen Reference Monitor.
- mmap, bereits gelesene Daten, FD-Reuse, Kernel-/Architekturgrenzen und kleine Messstichproben werden genannt.
- Future Work folgt den Ergebnissen: stabile Nutzungsidentität, weitere Vermittlungspfade, weniger invasiver Entzug, Last-/Portabilitätstests.

## 4. Kritikpunkte

Keine eigenständigen P0-/P1-Mängel in diesem Kapitel festgestellt. Die nachstehenden Querverweise bezeichnen konkrete Folgewirkungen anderer Kapitel, nicht fehlende Forschungsfrage oder fehlendes Fazit.

**Kapitelübergreifende Befunde:** F02/F04/F07/F08 aus den Einzelreviews gelten auch für die zusammenfassenden Aussagen über Zielerreichung, konsistente Generationen und Teststand. F05/F06/F14 müssen in §7.2 als zusätzliche Grenzen aufgenommen werden; die dortige Best-Effort-Diskussion deckt blockierte Updater, Linkverlust und Instruktionspatch-Risiken noch nicht ab.

## 5. Fehlende Inhalte

Ein kurzer Absatz sollte die Grenzen gruppieren: (1) Implementierung: blockierende Scans, ungesicherter Link-Lebenszyklus, Bank-Leserschutz, ptrace-Härtung; (2) Ansatz: nur file_open, kein Widerruf bereits gelesener Daten, FD-Close beseitigt mmap nicht; (3) Evaluation: nur einzelne Plattform und begrenzte Integrationstests. Das verhindert, lösbare Implementierungsprobleme als prinzipielle eBPF-Unmöglichkeit zu behandeln.

## 6. Überflüssige oder redundante Inhalte

Die vollständige Wiederholung sämtlicher Performancezahlen ist nicht zwingend, aber noch vertretbar. Bei Kürzung lieber Befund und Einschränkung bewahren als zusätzliche Resultattabellen wiederholen.

## 7. Quellen und Belege

Ein Fazit benötigt keine neuen Quellen, wenn es auf korrekt belegte Ergebnisse zurückführt. Neue stärkere Sicherheits- oder Portabilitätsbehauptungen wären zu vermeiden; solche werden hier weitgehend nicht aufgestellt.

## 8. Bezug zum Quellcode

Die Beschreibung von Maps, Tail Calls, Real UID und integrierten PDP-Funktionen ist korrekt. Die Aussage zur verbleibenden Clippy-Ursache ist nur für den historischen Messstand zutreffend. Die bloße gemeinsame Policysemantik garantiert keine identischen Anfragen bei veränderten Credentials oder threadbezogenem comm.

## 9. Beitrag zur Forschungsfrage

Antwort rekonstruiert: Umsetzung durch kompakte Kernelentscheidungen plus ereignisbasierte Userspace-Nachkontrolle ist möglich; vollständige fortdauernde Kontrolle wird nicht erreicht. Evidenz: Code, 59 lokale Tests, 17 E2E-Szenarien, Charakterisierungen und Rohmessungen. Für einen begrenzten Machbarkeitsnachweis grundsätzlich ausreichend; die pauschale Erfüllung aller Anforderungen bleibt zu korrigieren.

## 10. Wichtigste Maßnahmen

1. Zielerreichung mit korrigierter FA-06-Bewertung und tatsächlichem Teststand abgleichen (F02/F08).
2. Blockierung, Link-Lebensdauer und ptrace-Integrität als heutige Grenzen ergänzen (F05/F06/F14).
3. Konsistenz und nicht vollständig E2E geprüfte Trigger differenziert zusammenfassen (F04/F07).


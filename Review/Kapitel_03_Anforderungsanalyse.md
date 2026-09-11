# Review Kapitel 3 – Anforderungsanalyse

Stand: 11.09.2026. Begutachtet: aktueller Arbeitsbaum und vorhandene PDF, S. 16–18. Seitenangaben beziehen sich auf die gedruckten Seitenzahlen der 75-seitigen PDF. F-IDs sind reviewweit eindeutig; Querverweise bezeichnen denselben Befund und keine zusätzlichen Mängel.

## 1. Aufgabe des Kapitels

Die Forschungsfrage ist in überprüfbare Ziele und Akzeptanzkriterien zu übersetzen. Diese müssen in der Evaluation unverändert erkennbar sein und dürfen Grenzen des Prototyps nicht verdecken.

## 2. Gesamteindruck

**solide, aber überarbeitungsbedürftig.** Die Unterteilung in FA, OA und EA ist zweckmäßig. Zwei Anforderungspaare bleiben methodisch inkonsistent: garantierter FD-Entzug und nicht operationalisierte Performanceangemessenheit.

## 3. Stärken

- FA-08/FA-09 trennen vollständige Generationen und syntaktisch-semantische Validierung nachvollziehbar.
- FA-10 formuliert tatsächlich überprüfbare Namensregeln.
- Das lesende Administrationstool wird als eigenständige, begrenzte Funktion beschrieben.
- Die Anforderungen bleiben auf einen Bachelorprototyp zugeschnitten.

## 4. Kritikpunkte

### F02 – Kritikpunkt: FA-06 wird stärker gefordert als nachgewiesen

**Fundstelle:** §3.1 FA-06, PDF S.16–17, thesis/sections/03-anforderungsanalyse.tex:43; §6.3.4, S.68–69, 06-evaluation.tex:510; §7.2, S.71.

**Priorität:** P1.

**Kategorie:** Anforderungen; Argumentation; Evaluation.

**Problem:** FA-06 verlangt, bestehende Zugriffe „unmittelbar“ zu beenden, und das Akzeptanzkriterium verlangt den erfolgreichen selektiven Close. §6.3.4 erklärt sämtliche FA als erfüllt. E2E-17 dokumentiert jedoch ausdrücklich nicht geschlossene verletzende FDs bei Attach-Konflikt. Die spätere Best-Effort-Einordnung und der Ausschluss von mmap lösen diesen Widerspruch innerhalb des FD-Scopes nicht.

**Warum ist das problematisch?** Die Arbeit verwendet unterschiedliche Maßstäbe für Soll und Ergebnis. Auch ohne Echtzeitanforderung ist garantierter Erfolg etwas anderes als ein erfolgreicher Versuch unter Testbedingungen.

**Auswirkungen:** Unterbricht die Kette Anforderung → Test → Zielerreichung, ohne den Machbarkeitsnachweis insgesamt zu widerlegen.

**Lösung A – empfohlen:** FA-06 in der Auswertung als teilweise erfüllt einstufen, Erfolgsbedingungen und fehlende Zeitgarantie nennen; historische Zielsetzung und erreichte Einschränkung transparent unterscheiden.

**Lösung B – Alternative:** FA-06 nachvollziehbar in eine prototypische Versuchsanforderung mit expliziten Voraussetzungen und einer eigenen Fehlerfallanforderung überführen; die Scope-Präzisierung offenlegen, statt Kriterien still nachträglich abzuschwächen.

**Empfehlung des Gutachters:** A ist für die Endfassung am saubersten und schnellsten: das negative Ergebnis wissenschaftlich anerkennen.

**Aufwand:** mittel: 30 Minuten bis 2 Stunden.

**Erwarteter Nutzen:** sehr hoch.

**Relevanz für die Benotung:** hoch: beeinflusst die Glaubwürdigkeit der Anforderungserfüllung.

### F15 – Kritikpunkt: OA-03 misst Untersuchung statt Angemessenheit

**Fundstelle:** §3.2 OA-03, PDF S.18; §6.3.4, S.69; 03-anforderungsanalyse.tex:92.

**Priorität:** P2.

**Kategorie:** Anforderungen; Methodik.

**Problem:** Die Anforderung fordert keine unverhältnismäßige Verlangsamung; das Akzeptanzkriterium verlangt lediglich eine Betrachtung der Laufzeit. Entsprechend wird OA-03 als erfüllt bewertet, obwohl die Arbeit zu Recht keine Akzeptanzgrenze benennt.

**Warum ist das problematisch?** Eine erfolgte Messung kann keine nicht definierte Angemessenheit bestätigen. Der Text relativiert das später gut, beseitigt aber nicht das unpassende Anforderungspaar.

**Auswirkungen:** Kleiner, aber echter Bruch zwischen Anforderung und Operationalisierung.

**Lösung A – empfohlen:** OA-03 als exploratives Charakterisierungsziel formulieren und die nicht beurteilte Praxistauglichkeit getrennt nennen.

**Lösung B – Alternative:** Eine vorab sachlich hergeleitete, an einem Einsatzszenario orientierte Zielgröße definieren; keinesfalls nachträglich einen zum Ergebnis passenden Grenzwert wählen.

**Empfehlung des Gutachters:** A passt zur vorliegenden Machbarkeitsarbeit.

**Aufwand:** gering: < 30 Minuten.

**Erwarteter Nutzen:** mittel.

**Relevanz für die Benotung:** gering bis mittel: methodische Präzision.


**Kapitelübergreifende Befunde:** F04 betrifft die tatsächliche Reichweite der für FA-08 herangezogenen Konsistenzarchitektur. F08 betrifft die Nachweisgrundlage für OA-04.

## 5. Fehlende Inhalte

Es fehlt eine knappe Zuordnung jeder Anforderung zu Ursprung und späterer Evidenz. Eine zusätzliche Tabelle mit FA/OA → Abschnitt/Test-ID → Ergebnis würde die vorhandenen Inhalte verbinden; kein umfangreicher Requirements-Prozess nötig. Erfolgsbedingungen des FD-Entzugs und die Vertrauensannahmen sollten hier verankert oder auf Kapitel 4 verwiesen werden.

## 6. Überflüssige oder redundante Inhalte

Keine gravierende Überlänge. Allgemeine Erläuterungen der drei Anforderungstypen könnten kürzer ausfallen.

## 7. Quellen und Belege

Eigene Projektanforderungen benötigen grundsätzlich keine externe Quelle. Sicherheitszusagen benötigen hingegen nachvollziehbare Herleitung und empirische beziehungsweise technische Evidenz; Literatur allein kann FA-06 nicht erfüllen.

## 8. Bezug zum Quellcode

Die meisten funktionalen Anforderungen sind implementiert. FA-06 stößt an explizite geschützte PIDs, Attach-Rechte, Task-/FD-Races und fehlende Fortschrittsgarantien. Das ist mit einer prototypischen Nachkontrolle vereinbar, aber nicht mit unbedingter Erfüllung.

## 9. Beitrag zur Forschungsfrage

Das Kapitel schafft den Prüfmaßstab der Arbeit. Gerade deshalb fällt die spätere pauschale Erfüllung aller FA ins Gewicht.

## 10. Wichtigste Maßnahmen

1. FA-06 ehrlich als teilweise erfüllt bilanzieren oder transparent präzisieren (F02).
2. OA-03 als Charakterisierungsziel operationalisieren (F15).
3. Anforderungs-Evidenz-Tabelle ergänzen und OA-04 anhand des finalen Archivs bewerten (F08).


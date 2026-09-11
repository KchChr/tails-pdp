# Review Kapitel 1 – Einleitung

Stand: 11.09.2026. Begutachtet: aktueller Arbeitsbaum und vorhandene PDF, S. 5–6. Seitenangaben beziehen sich auf die gedruckten Seitenzahlen der 75-seitigen PDF. F-IDs sind reviewweit eindeutig; Querverweise bezeichnen denselben Befund und keine zusätzlichen Mängel.

## 1. Aufgabe des Kapitels

Die Einleitung muss das Problem dynamisch veränderlicher Autorisierung von der punktuellen Dateiöffnungsentscheidung abgrenzen, eine bearbeitbare Forschungsfrage stellen und den späteren Machbarkeitsnachweis vorbereiten.

## 2. Gesamteindruck

**gut.** Die Frage nach prototypischer Umsetzung und technischen Einschränkungen ist präzise, für eine Bachelorarbeit angemessen und wird in Kapitel 7 wieder aufgegriffen. Die bewusste Beschränkung auf ausgewählte ASBAC-Prinzipien verhindert einen überzogenen Anspruch.

## 3. Stärken

- Die Forschungsfrage benennt Technologie, Operation und die besonders schwierige Nachkontrolle bereits bestehender Zugriffe.
- Die Zielsetzung spricht zutreffend von einem Entzugsversuch und schließt einen allgemeinen SAPL-PDP ausdrücklich aus.
- Der Aufbauabschnitt entspricht den tatsächlich vorhandenen sieben Kapiteln.

## 4. Kritikpunkte

Keine eigenständigen P0-/P1-Mängel in diesem Kapitel festgestellt. Die nachstehenden Querverweise bezeichnen konkrete Folgewirkungen anderer Kapitel, nicht fehlende Forschungsfrage oder fehlendes Fazit.

**Kapitelübergreifende Befunde:** F02 betrifft einen Widerspruch des späteren Anforderungskapitels zur hier angemessen formulierten Zielsetzung. Die Einleitung sollte dafür nicht wieder auf eine Garantie verschärft werden.

## 5. Fehlende Inhalte

Ein kurzer konkreter Anwendungsfall würde die Motivation anschaulicher machen, ist aber kein zwingend fehlender wissenschaftlicher Inhalt. Die Forschungsfrage selbst fehlt nicht. Eine Behauptung bislang unerreichter Forschungsergebnisse wird nicht aufgestellt.

## 6. Überflüssige oder redundante Inhalte

Keine wesentliche Redundanz in diesem kurzen Kapitel. Die allgemeine Eingangsaussage zur Bedeutung von Linux-Sicherheit ist austauschbar, aber nicht notenentscheidend.

## 7. Quellen und Belege

Der Verweis auf die offizielle LSM-Dokumentation trägt die Framework-Aussage. Die Beschränkung des file_open-Hooks wird in Kapitel 2 und durch die Implementierung genauer ausgeführt; kein zusätzlicher Beleg für jeden Satz nötig.

## 8. Bezug zum Quellcode

file_open sowie Policy-/Attributloader und FD-Nachbewertung sind tatsächlich vorhanden. Die Einleitung verspricht keine vollständige ASBAC-Subscription-Engine. Für die Echtintegration des Zeitgrenzentriggers bleibt die in F07 genannte Evidenzlücke.

## 9. Beitrag zur Forschungsfrage

Sie definiert exakt den zweigeteilten Prüfauftrag: Wie ist die Umsetzung möglich, und wo endet ihre Aussagekraft? Beide Teile werden später grundsätzlich beantwortet.

## 10. Wichtigste Maßnahmen

1. Die vorsichtige Formulierung „Entzug versuchen“ beibehalten und FA-06/Ergebnisbewertung daran abgleichen (F02).
2. Optional einen vier- bis fünfzeiligen Anwendungsfall ergänzen; Aufwand gering, Nutzen mittel, Benotungsrelevanz gering.


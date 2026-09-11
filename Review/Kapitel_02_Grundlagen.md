# Review Kapitel 2 – Grundlagen

Stand: 11.09.2026. Begutachtet: aktueller Arbeitsbaum und vorhandene PDF, S. 7–15. Seitenangaben beziehen sich auf die gedruckten Seitenzahlen der 75-seitigen PDF. F-IDs sind reviewweit eindeutig; Querverweise bezeichnen denselben Befund und keine zusätzlichen Mängel.

## 1. Aufgabe des Kapitels

Das Kapitel muss Reference Monitor, ABAC/ASBAC, logische PDP-/PEP-Rollen und Linux-Mechanismen so erklären, dass die spätere hybride Architektur und ihre Grenzen beurteilt werden können.

## 2. Gesamteindruck

**gut.** Die theoretischen Begriffe sind sinnvoll ausgewählt. Besonders gelungen ist die explizite Abgrenzung von FD-Rekonstruktion zu einer ASBAC-Subscription. Die zentralen Definitionen sind durch reale, weitgehend passende Quellen gedeckt.

## 3. Stärken

- Reference-Monitor-Eigenschaften und vollständige Vermittlung werden als theoretischer Maßstab eingeführt; das Fazit behauptet später keinen vollständigen Reference Monitor.
- ASBAC und verwandte Usage-Control-Konzepte werden unterschieden. Das Heutelbeck-Demopaper trägt die beschriebene Publish-Subscribe-Semantik.
- PDP/PEP werden als logische Rollen behandelt, die im selben technischen Pfad zusammenfallen dürfen.
- FD, offene Dateibeschreibung, dup/fork, mmap, laufende E/A und TOCTTOU werden für eine Bachelorarbeit erfreulich differenziert eingeordnet.

## 4. Kritikpunkte

### F11 – Kritikpunkt: Bibliographische Versionen und Fundstellen präzisieren

**Fundstelle:** §2.4 und §4.6.11; Literatur [20], PDF S.74; thesis/literatur.bib:oasisXacml30; Literatur [1], S.73.

**Priorität:** P2.

**Kategorie:** Quelle; formale Korrektheit.

**Problem:** XACML wird mit Jahr 2010 geführt; die zitierte URL zeigt Version 3.0 Plus Errata 01 vom 12.07.2017 und verweist auf den Standard vom 22.01.2013. Anderson ist als realer Bericht verifiziert, die alte angegebene URL war hier aber nicht abrufbar; der NIST-Archivpfad funktioniert. Mehrere Titel verlieren in plainnat die fachlich richtige Großschreibung (ABAC, BPF, Linux, TLA+).

**Warum ist das problematisch?** Quelle, Version und Jahr müssen zusammenpassen. Ein pauschaler Buch-/Webverweis erschwert gerade bei konkreten technischen Aussagen die Kontrolle.

**Auswirkungen:** Reparierbare Quellenmängel; kein Nachweis erfundener zentraler Literatur.

**Lösung A – empfohlen:** XACML konkret als Standard 2013 oder Erratafassung 2017 zitieren und passende URL/Jahr verwenden; Anderson mit Band II und §4.1.3/S.15 präzisieren; Acronyme in BibTeX schützen.

**Lösung B – Alternative:** Den vorhandenen Stil beibehalten, nur falsches Jahr, veralteten Link und die zentralen Abschnittsfundstellen korrigieren.

**Empfehlung des Gutachters:** A; alle Angaben aus den tatsächlich geöffneten Primärquellen übernehmen, keine vermeintlichen Publikationsjahre aus Abrufdaten ableiten.

**Aufwand:** mittel: 30 Minuten bis 2 Stunden.

**Erwarteter Nutzen:** mittel.

**Relevanz für die Benotung:** gering bis mittel: punktuelle formale und bibliographische Sorgfalt.


**Kapitelübergreifende Befunde:** Die falsche Einordnung klassischer LSMs entsteht in Kapitel 4 (F03), nicht durch die korrekte allgemeine Einführung hier. F06 verlangt später eine konkrete Anwendung des Reference-Monitor-Maßstabs auf die TCB.

## 5. Fehlende Inhalte

Eine knappe Vergleichstabelle ASBAC/SAPL – verwandte fortdauernde Autorisierung – eigener Prototyp könnte die Einordnung verdichten. Eine systematische Literaturübersicht als eigenes Kapitel ist für die eng formulierte Machbarkeitsfrage nicht zwingend. Das kurze Demopaper genügt für die verwendete Definition; für tiefergehende Architekturbehauptungen wäre eine ausführlichere ASBAC-Primärarbeit sinnvoll.

## 6. Überflüssige oder redundante Inhalte

Die Abschnitte zu Generationen und Prototypkomponenten nehmen Entwurfsdetails vorweg. Allgemeine Begriffe hier behalten; konkrete Bank- und Loadermechanik in Kapitel 4/5 konzentrieren. Aufwand mittel, Nutzen mittel, geringe Benotungsrelevanz.

## 7. Quellen und Belege

Quellen_Audit.md dokumentiert die 36 tatsächlich zitierten Schlüssel, konkrete Deckung und Abrufgrenzen. Keine Grundlage für den Vorwurf erfundener Kernliteratur. Der heutige Abruf verifiziert nicht rückwirkend den Inhalt am angegebenen Abrufdatum.

## 8. Bezug zum Quellcode

512-Byte-Stack, feste Strukturen und no_std passen zur Implementierungsentscheidung. Der Code nutzt Debug-Derives in der gemeinsamen Crate; daraus folgt kein Widerspruch zur zitierten Einschränkung tatsächlich ausgeführter Formatierung im eBPF-Pfad. Die Real-UID-Semantik ist durch Kernelhelper, lokalen Aya-Commit und /proc-Manpage gestützt.

## 9. Beitrag zur Forschungsfrage

Das Kapitel liefert sowohl das Modell dynamischer Entscheidungsgrundlagen als auch die Gründe, weshalb eine Dateiöffnung allein keine fortdauernde Durchsetzung gewährleistet.

## 10. Wichtigste Maßnahmen

1. XACML-Version/Jahr und Anderson-Fundstelle berichtigen (F11).
2. Die fachlich korrekten Abgrenzungen von ASBAC und FD-Nachkontrolle beibehalten.
3. Optional den Stand der Technik durch eine knappe Gegenüberstellung verdichten.


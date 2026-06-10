# Inside Requirements

Source: SlideShare document "Inside Requirements" by Kevlin Henney.

## Kurzfassung

Der Artikel argumentiert, dass die verbreitete Unterscheidung zwischen
"functional" und "non-functional requirements" ungenau ist. Der Begriff
"non-functional" fasst zu viele unterschiedliche Qualitaeten in eine
Restkategorie und verschleiert, worum es wirklich geht.

Henney schlaegt stattdessen drei Kategorien vor:

## Functional Requirements

Functional requirements beschreiben, was ein System tut. Sie beziehen sich auf
Zweck, Verhalten, Regeln und beobachtbare Effekte des Systems.

Typisch fuer diese Anforderungen ist, dass sie klar pruefbar sind: Eine
Anforderung ist erfuellt oder nicht erfuellt. Beispiele sind Berechnungen,
Zustandsaenderungen, Vertragsbedingungen von Schnittstellen oder Regeln fuer
Objektgleichheit.

Der Artikel stellt heraus, dass funktionale Anforderungen oft gut automatisiert
getestet werden koennen, vom Gesamtsystem bis hinunter zu einzelnen Methoden
oder Komponenten.

## Operational Requirements

Operational requirements beschreiben, wie gut ein System seine Funktion im
Betrieb erfuellt. Dazu gehoeren unter anderem Performance, Durchsatz,
Speicherbedarf, Skalierbarkeit, Usability, Verfuegbarkeit und Manageability.

Diese Anforderungen sind selten binaer. Sie sind oft graduell, statistisch oder
teilweise subjektiv. Dadurch lassen sie sich schwerer direkt automatisiert
testen als funktionale Anforderungen.

Henney betont, dass operative Qualitaeten haeufig quer zur Codestruktur liegen.
Sie entstehen aus dem Zusammenspiel vieler Teile und sind deshalb schwerer zu
entwerfen, zu messen und zu garantieren. Prototyping wird als wichtiges Mittel
genannt, um Annahmen ueber Performance, Skalierung oder Bedienbarkeit frueh zu
ueberpruefen.

## Developmental Requirements

Developmental requirements beschreiben die Qualitaet aus Sicht der Entwickler.
Sie betreffen Eigenschaften wie Portabilitaet, Verstaendlichkeit,
Aenderbarkeit und allgemeine Implementierungsqualitaet.

Diese Anforderungen sind fuer Kunden oft nicht direkt sichtbar, beeinflussen
aber langfristig, wie teuer und riskant Weiterentwicklung wird. Der Artikel
warnt davor, dass schlecht strukturierter Code mit der Zeit ueberproportional
teuer zu aendern wird.

Henney sieht diese Anforderungen als Verantwortung der Programmierer. Sie
muessen nicht immer explizit vom Kunden eingefordert werden, sondern gehoeren
zum professionellen Wissen, das Entwickler in ein Projekt einbringen.

## Kernaussagen

- Anforderungen formen ein System nicht nur ueber Features, sondern auch ueber
  Betriebsqualitaet und Implementierungsqualitaet.
- "Non-functional requirements" ist als Begriff zu vage und irrefuehrend.
- Functional requirements sind meist objektiv und automatisiert testbar.
- Operational requirements bestimmen die Qualitaet der Nutzererfahrung.
- Developmental requirements bestimmen die Qualitaet der Entwicklererfahrung.
- Gute Software braucht nicht nur korrektes Verhalten, sondern auch gute
  Betriebs- und Weiterentwicklungseigenschaften.

## Bedeutung fuer Softwareentwicklung

Der Artikel fordert dazu auf, Anforderungen praeziser zu benennen. Statt alles
Nicht-Funktionale in eine Kategorie zu werfen, sollten Teams unterscheiden, ob
es um Verhalten, Betrieb oder Entwicklungsqualitaet geht. Diese Unterscheidung
hilft, passende Tests, Architekturentscheidungen und Verantwortlichkeiten
abzuleiten.

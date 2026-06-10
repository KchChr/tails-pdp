# Regeln fuer Anforderungsarten

Abgeleitet aus den im Text "Inside Requirements" von Kevlin Henney
beschriebenen Anforderungsarten.

## Ueberblick

Anforderungen sollten nicht nur in "funktional" und "nicht-funktional"
aufgeteilt werden. Der Text argumentiert fuer eine praezisere Unterscheidung:

- Funktionale Anforderungen
- Operative Anforderungen
- Entwicklungsbezogene Anforderungen

Jede Art beantwortet eine andere Frage und sollte in Analyse, Design, Test und
Implementierung unterschiedlich behandelt werden.

## Funktionale Anforderungen

Funktionale Anforderungen beschreiben, was das System tut.

### Regeln

- Eine funktionale Anforderung sollte beobachtbares Systemverhalten beschreiben.
- Eine funktionale Anforderung sollte Zweck, Wirkung oder regelbasiertes
  Verhalten definieren.
- Eine funktionale Anforderung sollte so praezise sein, dass entschieden werden
  kann, ob sie erfuellt ist.
- Eine funktionale Anforderung sollte in der Regel als bestanden oder nicht
  bestanden pruefbar sein.
- Eine funktionale Anforderung sollte vage Qualitaetsbegriffe vermeiden, sofern
  diese nicht in konkretes Verhalten uebersetzt werden koennen.
- Eine funktionale Anforderung sollte auf verschiedenen Ebenen formulierbar
  sein: System, Subsystem, Komponente, Klasse oder Methode.
- Eine funktionale Anforderung auf niedrigerer Ebene kann aus einer
  funktionalen Anforderung auf hoeherer Ebene abgeleitet sein.
- Eine funktionale Anforderung sollte, wenn moeglich, durch Beispiele, Tests
  oder Verträge abgesichert werden.
- Wenn eine funktionale Anforderung nicht erfuellt ist, sollte dies als
  Verhaltensfehler behandelt werden.
- Funktionale Anforderungen eignen sich besonders gut fuer automatisierte Tests.

### Typische Nachweise

- Akzeptanztests
- Unit-Tests
- Vorbedingungen und Nachbedingungen
- Schnittstellenvertraege
- Geschaeftsregeln
- Deterministische Beispiele
- Eingabe-/Ausgabe-Faelle

### Typische Fragen

- Was muss das System tun?
- Welches sichtbare Ergebnis soll diese Aktion erzeugen?
- Welche Regel steuert dieses Verhalten?
- Welche Zustandsaenderung soll stattfinden?
- Was muss vor oder nach dieser Operation immer gelten?
- Woran erkennen wir objektiv, ob dieses Verhalten korrekt ist?

## Operative Anforderungen

Operative Anforderungen beschreiben, wie gut das System seine Funktion im
Betrieb erfuellt.

### Regeln

- Eine operative Anforderung sollte die Servicequalitaet aus Sicht von Nutzern
  oder Betreibern beschreiben.
- Eine operative Anforderung sollte, soweit moeglich, messbar formuliert sein.
- Eine operative Anforderung sollte nicht als einfache Ja-/Nein-Regel behandelt
  werden, sofern kein klarer Grenzwert definiert ist.
- Eine operative Anforderung kann statistische, kontextbezogene oder wiederholte
  Messung erfordern.
- Operative Anforderungen schneiden haeufig quer durch Module und koennen nicht
  immer einer einzelnen isolierten Komponente zugeordnet werden.
- Operative Anforderungen sollten Architektur- und Designentscheidungen
  beeinflussen.
- Operative Anforderungen sollten durch Prototypen oder Messungen ueberprueft
  werden, wenn Annahmen riskant sind.
- Operative Anforderungen sollten nicht hinter Abstraktionen versteckt werden,
  wenn die betreffende Qualitaet fuer Nutzer oder Aufrufer relevant ist.
- Operative Anforderungen koennen Teil eines Vertrags sein, brauchen aber oft
  reichere Ausdrucksformen als Vorbedingungen und Nachbedingungen.
- Wenn operative Anforderungen nicht beruecksichtigt werden, kann ein System
  funktional korrekt, aber schlecht benutzbar sein.

### Typische Nachweise

- Performance-Benchmarks
- Lasttests
- Verfuegbarkeitsmessungen
- Usability-Studien
- Speicherprofiling
- Skalierbarkeitstests
- Durchsatzmessungen
- Latenzbudgets
- Operative Prototypen

### Typische Fragen

- Wie schnell muss das System reagieren?
- Welche Last muss es verarbeiten?
- Wie viel Speicher darf es verwenden?
- Wie verfuegbar muss es sein?
- Wie benutzbar ist es fuer die vorgesehenen Nutzer?
- Wie verhaelt es sich unter Stress?
- Welche Servicequalitaet wird erwartet?
- Welche Designannahmen muessen gemessen werden?

## Entwicklungsbezogene Anforderungen

Entwicklungsbezogene Anforderungen beschreiben die Qualitaet der Implementierung
aus Sicht der Entwickler.

### Regeln

- Eine entwicklungsbezogene Anforderung sollte Qualitaeten beschreiben, die
  zukuenftige Entwicklung beeinflussen.
- Eine entwicklungsbezogene Anforderung sollte Wartbarkeit, Aenderbarkeit,
  Verstaendlichkeit, Portierbarkeit oder aehnliche Implementierungsqualitaeten
  betreffen.
- Entwicklungsbezogene Anforderungen sollten als echte Anforderungen behandelt
  werden, auch wenn Kunden sie nicht ausdruecklich einfordern.
- Entwicklungsbezogene Anforderungen liegen vor allem in der Verantwortung von
  Entwicklern und technischen Entscheidern.
- Entwicklungsbezogene Anforderungen sollten Codestruktur, Benennung,
  Modularitaet, Abhaengigkeiten und Designgrenzen beeinflussen.
- Entwicklungsbezogene Anforderungen sollten beruecksichtigt werden, bevor Code
  teuer zu aendern wird.
- Entwicklungsbezogene Anforderungen sollten nicht abgewertet werden, nur weil
  sie fuer Nutzer nicht direkt sichtbar sind.
- Schlechte Entwicklungsqualitaet kann funktionale und operative Qualitaet mit
  der Zeit beeintraechtigen.
- Code sollte so geformt sein, dass wahrscheinliche zukuenftige Aenderungen zu
  vertretbaren Kosten moeglich sind.
- Ein System sollte vermeiden, Implementierungskomplexitaet anzusammeln, die
  jede weitere Aenderung unverhaeltnismaessig erschwert.

### Typische Nachweise

- Klare Codestruktur
- Kleine, kohäsive Module
- Verstaendliche Namen
- Automatisierte Regressionstests
- Geringe Kopplung
- Explizite Vertraege
- Einfache Abhaengigkeitsgrenzen
- Portierbarkeitspruefungen
- Refactoring-Historie
- Review-Feedback

### Typische Fragen

- Koennen Entwickler diesen Code verstehen?
- Kann das System ohne uebermaessiges Risiko geaendert werden?
- Kann die Implementierung bei Bedarf portiert werden?
- Sind Verantwortlichkeiten klar getrennt?
- Sind wichtige Annahmen explizit?
- Macht das Design wahrscheinliche Aenderungen leichter oder schwerer?
- Wird dieser Code mit der Zeit teurer zu aendern?
- Bewahren wir die Implementierungsqualitaet, waehrend sich das System
  weiterentwickelt?

## Klassifikationsregeln

Nutze diese Regeln, um eine Anforderung einzuordnen.

### Wenn sie Verhalten beschreibt

Ordne sie als funktional ein, wenn sie beantwortet:

- Was tut das System?
- Welches Ergebnis muss eintreten?
- Welche Regel muss eingehalten werden?
- Welche Zustandsaenderung ist erforderlich?

Beispielmuster:

> Wenn X passiert, muss das System Y tun.

### Wenn sie Servicequalitaet beschreibt

Ordne sie als operativ ein, wenn sie beantwortet:

- Wie schnell?
- Wie zuverlaessig?
- Wie skalierbar?
- Wie verfuegbar?
- Wie benutzbar?
- Wie ressourceneffizient?

Beispielmuster:

> Das System muss Y innerhalb von Grenze Z unter Bedingung X leisten.

### Wenn sie Implementierungsqualitaet beschreibt

Ordne sie als entwicklungsbezogen ein, wenn sie beantwortet:

- Wie leicht ist es zu verstehen?
- Wie leicht ist es zu aendern?
- Wie portierbar ist es?
- Wie wartbar ist es?
- Wie gut unterstuetzt der Code zukuenftige Arbeit?

Beispielmuster:

> Die Implementierung muss erlauben, Y zu aendern, ohne unverbundene Teile des
> Systems anzupassen.

## Praktische Handhabungsregeln

- Verwende "nicht-funktional" nicht als endgueltige Klassifikation, wenn eine
  praezisere Art verfuegbar ist.
- Formuliere vage Anforderungen in funktionale, operative oder
  entwicklungsbezogene Anforderungen um.
- Ordne unterschiedlichen Anforderungsarten unterschiedliche Validierungsmethoden
  zu.
- Nutze bevorzugt automatisierte Tests fuer funktionale Anforderungen.
- Nutze bevorzugt Messung, Profiling, Beobachtung und Experimente fuer operative
  Anforderungen.
- Nutze bevorzugt Code-Reviews, Architektur-Reviews, Refactoring-Disziplin und
  Wartbarkeitspruefungen fuer entwicklungsbezogene Anforderungen.
- Behandle Konflikte zwischen Anforderungsarten explizit.
- Lass funktionale Korrektheit nicht schlechte operative Qualitaet verdecken.
- Lass kurzfristige Lieferung nicht schlechte Entwicklungsqualitaet verdecken.
- Ueberpruefe abgeleitete Anforderungen auf niedrigerer Ebene erneut, wenn sich
  Anforderungen auf Systemebene veraendern.

## Haeufige Fehler

- Jede Qualitaetsanforderung als "nicht-funktional" bezeichnen.
- Performance oder Usability als nachtraegliches Detail behandeln.
- Annehmen, operative Qualitaeten koennten spaet ohne Designauswirkungen
  hinzugefuegt werden.
- Implementierungsqualitaet ignorieren, weil Kunden sie nicht direkt verlangen.
- Funktionale Anforderungen schreiben, die zu vage zum Testen sind.
- Operative Anforderungen ohne messbare Grenzwerte schreiben.
- Entwicklungsbezogene Anforderungen als optionale Aufraeumarbeit statt als
  Designbedingungen behandeln.
- Wichtige Performance- oder Komplexitaetseigenschaften hinter Abstraktion
  verstecken.

## Zusammenfassung

Funktionale Anforderungen definieren Verhalten.

Operative Anforderungen definieren Servicequalitaet.

Entwicklungsbezogene Anforderungen definieren Implementierungsqualitaet.

Ein nuetzliches Anforderungsmodell sollte diese Unterschiede klar benennen, weil
jede Art zu anderen Designentscheidungen, Validierungstechniken und
Verantwortlichkeiten fuehrt.

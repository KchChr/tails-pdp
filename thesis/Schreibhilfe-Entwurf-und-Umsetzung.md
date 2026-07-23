# Schreibhilfe: Entwurf und Umsetzung

## Ziel des Kapitels

Dieses Kapitel beantwortet: **Wie wurde die zuvor begruendete Konzeption technisch umgesetzt?**
Es beschreibt Verantwortlichkeiten, Datenstrukturen, Kontrollfluesse und Grenzen der tatsaechlichen
Implementierung. Messergebnisse und die Bewertung der Anforderungen gehoeren erst in die Evaluation.

**Abgrenzung:**

- **Konzeption:** Problem, Alternativen, Entscheidung und Begruendung.
- **Entwurf und Umsetzung:** konkrete Realisierung im Prototyp und ihre technischen Folgen.

## Vorgehen pro Unterabschnitt

1. Bestimme die Leserfrage, zum Beispiel: "Wie wird eine Policy sicher in die aktive Map-Generation uebernommen?"
2. Lies den betreffenden Codepfad vollstaendig: Eingabe, Verarbeitung, Ausgabe und Fehlerfall.
3. Formuliere den ersten Absatz nach dem folgenden Schema.
4. Ergaenze nur die Details, die zum Verstaendnis der Schnittstelle oder Entscheidung erforderlich sind.
5. Pruefe abschliessend, ob jede Aussage im Code oder in einer Quelle belegbar ist.

## Absatzschema

1. **Aufgabe oder Problem:** Welche Anforderung oder technische Schwierigkeit wird behandelt?
2. **Umsetzung:** Welche Komponente, Datenstruktur oder Schnittstelle uebernimmt die Aufgabe?
3. **Ablauf:** Welche Eingaben werden verarbeitet, welche Schritte erfolgen, welches Ergebnis entsteht?
4. **Fehlerverhalten oder Grenze:** Was geschieht bei ungueltigen Daten, Ausfall oder einer technischen Begrenzung?
5. **Konsequenz:** Welchen Nutzen oder welche Einschraenkung hat die Umsetzung fuer das Gesamtsystem?

### Vorlage

> [Komponente] uebernimmt [Aufgabe], damit [Anforderung oder Problem]. Dazu verarbeitet sie
> [Eingabe] und ueberfuehrt diese in [Struktur oder Ergebnis]. Anschliessend wird [Folgeschritt]
> ausgefuehrt. Tritt [Fehlerfall] auf, dann [Verhalten]. Dadurch [Konsequenz fuer Konsistenz,
> Sicherheit oder Nachvollziehbarkeit].

## Schreibregeln

- Einen Gedanken pro Absatz; meist drei bis sechs Saetze.
- Zuerst den Ablauf erklaeren, danach Namen von Crates, Strukturen oder Maps nennen.
- Fachliche Grundlagen und allgemeine Technik mit Quellen belegen. Die eigene Implementierung wird
  mit konkreten Codeverweisen beschrieben, nicht mit externen Quellen belegt.
- Praesens verwenden: "Der Policyloader liest ...", nicht "wird gelesen" ohne Akteur.
- Praezise Verben verwenden: Policies werden im Userspace **gelesen, validiert und in
  kernelgeeignete Map-Eintraege uebersetzt**; sie werden nicht "kompiliert".
- Keine Testergebnisse vorwegnehmen. Formulierungen wie "funktioniert erfolgreich" oder
  "ist performant" gehoeren in die Evaluation.

## Kurzcheck vor dem Weitergehen

- Ist klar, **was** die Komponente tut?
- Ist klar, **warum** sie an dieser Stelle notwendig ist?
- Ist nachvollziehbar, **welche Daten** hinein- und herausfliessen?
- Ist beschrieben, **was bei Fehlern** oder ungueltigen Eingaben geschieht?
- Ist die Abgrenzung zu anderen Komponenten eindeutig?
- Wiederholt der Abschnitt keine Begruendung aus der Konzeption?

## Wiederkehrende Fragen im Prototyp

- Welche gepinnte eBPF-Map wird gelesen oder geschrieben?
- Welche Generation oder Bank ist aktiv, und wann wird sie umgeschaltet?
- Laeuft die Logik im Userspace, im Kernelspace-PEP oder im Userspace-PEP?
- Welche eBPF-Grenze beeinflusst die Realisierung: feste Map-Groesse, kein Heap, Stack,
  Verifier oder Tail Calls?
- Welche Anforderung wird damit umgesetzt oder eingeschraenkt?

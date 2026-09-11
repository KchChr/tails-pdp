# Abschließende Gesamtbewertung der Bachelorarbeit

**Begutachteter Stand:** 11.09.2026, aktueller Arbeitsbaum bei HEAD `756af74` einschließlich vorbestehender Änderungen und vorhandener 75-seitiger PDF. Dieses Gutachten wurde nach den sieben Kapitelanalysen, dem [Quellen-Audit](Quellen_Audit.md) und dem [Code-Thesis-Audit](Code_Thesis_Audit.md) erstellt. Umfang und Nachweisgrenzen stehen im [Prüfprotokoll](Pruefprotokoll.md). Seitenangaben der Einzelreviews beziehen sich auf die Abgabe-PDF. Eine institutionelle Bewertungsmatrix wurde nicht vorgelegt; die Note ist eine begründete Gutachtersimulation.

## 1. Executive Summary

**Ist die Arbeit in ihrer aktuellen Form abgabereif? Noch nicht – wesentliche Änderungen notwendig.**

Die Arbeit behandelt eine anspruchsvolle und für eine Informatik-Bachelorarbeit angemessen begrenzte Fragestellung. Sie entwickelt einen substantiellen Rust-/Aya-Prototyp, der Dateiöffnungen über eBPF-LSM anhand vorbereiteter Policies und Attribute prüft und bestehende File Descriptors im Userspace nachbewertet. Die Entscheidung für eine hybride Architektur ist grundsätzlich nachvollziehbar. Gemeinsam verwendete Auswertungslogik, feste Map-Datenstrukturen, kontrollierte Generationenaktivierung und die breite funktionale Evaluation sind konkrete Stärken.

Wissenschaftlich überzeugt die Arbeit besonders dort, wo sie den eigenen Scope klar begrenzt: kein vollständiges SAPL, keine vollständige Vermittlung sämtlicher Dateinutzung, kein zuverlässiger Widerruf bereits bestehender Mappings. Negative Ergebnisse werden sichtbar berichtet. Die Messwerte lassen sich aus den archivierten Rohdaten korrekt nachrechnen. Eine solche Transparenz ist positiv zu bewerten.

Die aktuelle Abgabefassung enthält jedoch einen **sichtbaren TODO-Platzhalter als Abbildung 2 auf Seite 39**. Schwerer als dieser schnell behebbaren Präsentationsfehler wiegen mehrere Diskrepanzen zwischen Anforderung, Beschreibung und Evidenz:

- FA-06 fordert einen stärkeren Entzug, als die ausdrücklich als Best effort implementierte Lösung gewährleistet. Die spätere pauschale Bewertung aller funktionalen Anforderungen als erfüllt ist damit nicht konsistent.
- Die beschriebenen während eines FD-Scans weiterlaufenden Updates laufen tatsächlich in Zweigen desselben Tokio-Tasks. Der synchrone Scan und blockierende ptrace-Wartepfade verhindern deren Fortschritt.
- Die Veröffentlichung einer vorbereiteten Bank ist nachvollziehbar implementiert, eine uneingeschränkte stabile Lesesicht über Bankwiederverwendung hinweg aber nicht hergeleitet.
- Runtime-Ausfall und intrusive ptrace-Fehlerpfade sind in der Sicherheitsbilanz unvollständig berücksichtigt.
- Der endgültige Arbeitsbaum und die archivierten Prüfstände sind noch nicht durch einen abschließenden Nachweis zusammengeführt; zwei zentrale dynamische FD-Trigger sind nicht separat Ende-zu-Ende belegt.

Das sind keine Gründe, die erhebliche Eigenleistung oder die bestandenen Tests abzuwerten, als wären sie nicht vorhanden. Sie verhindern aber eine sehr gute Bewertung und sollten vor einer Abgabe korrigiert werden. **Eine grundlegende Neuentwicklung wird nicht verlangt.** In vielen Fällen ist die richtige Maßnahme, den tatsächlichen Zustand präzise zu beschreiben und die Reichweite einer Aussage zu begrenzen. Wo weitere Tests möglich sind, haben zwei dynamische Entzugsszenarien und ein sauber dokumentierter finaler Linux-Lauf den größten Nutzen.

**Realistische Gesamtnote derzeit: 2,3; plausibler Korridor: 2,0–2,7.** Nach substantieller Korrektur der genannten Punkte und Schließen der wichtigsten Evidenzlücken erscheint **1,7** erreichbar. Ein bloßes Entfernen des TODO genügt dafür nicht.

## 2. Forschungsfrage und wissenschaftlicher Beitrag

Die Forschungsfrage lautet:

> Wie kann Attribute Stream-Based Access Control für Dateiöffnungen prototypisch mittels eBPF-LSM unter Linux umgesetzt werden, und welche technischen Einschränkungen ergeben sich insbesondere bei der nachträglichen Kontrolle bereits bestehender Dateizugriffe?

Sie ist eindeutig, technisch relevant und für den Bachelorumfang sinnvoll eingeschränkt. Der Beitrag besteht in der Übertragung ausgewählter ASBAC-Prinzipien auf einen konkreten Linux-Durchsetzungspfad und der experimentellen Untersuchung der Grenzen des nachträglichen FD-Entzugs. Die Arbeit muss keine neue allgemeine Zugriffskontrolltheorie begründen.

**Welche Antwort liefert die Thesis?** Policies werden im Userspace verarbeitet und mit dynamischen Attributen in begrenzten Maps bereitgestellt. Ein kleines eBPF-LSM-Programm entscheidet bei file_open. Ein Userspace-PEP reagiert auf aktivierte Änderungen und Zeitgrenzen, untersucht bestehende reguläre Datei-FDs und versucht einen selektiven Entzug durch ptrace-gestütztes close.

**Welche Evidenz trägt diese Antwort?** Quellcode, Unit-Tests, 17 E2E-Szenarien und ergänzende Performance-, Kapazitäts-, Stabilitäts-, Charakterisierungs- und Race-Experimente zeigen wesentliche Funktionen. Insbesondere sind reale erlaubte/verweigerte Opens und FD-Entzüge belegt. CHAR-01 zeigt die fortbestehende mmap-Nutzung; der Attach-Konflikt zeigt die Grenzen des Entzugs.

**Reicht das aus?** Für die grundsätzliche Machbarkeit im definierten Scope überwiegend ja. Für eine garantierte, zeitlich zuverlässige Nachkontrolle aller bestehenden Zugriffe nein. Die vollständige Integration von rein attribut- und rein zeitbedingtem FD-Entzug bleibt unvollständig nachgewiesen (F07). Die Frage wird somit **substanziell beantwortet**, die behauptete Anforderungserfüllung ist stellenweise umfassender als der Nachweis. Die Eigenleistung liegt klar in Entwurf, Implementierung und experimenteller Untersuchung; sie darf als prototypische Umsetzung ausgewählter Prinzipien benannt werden.

## 3. Roter Faden und Gesamtargumentation

| Übergang | Bewertung |
|---|---|
| Problem → Forschungsfrage | Nachvollziehbar: Öffnungsprüfung allein reicht für veränderliche Autorisierung bestehender Zugriffe nicht aus. |
| Forschungsfrage → Anforderungen | Gut strukturiert; FA-06 überzieht die spätere Best-effort-Lösung, OA-03 besitzt keinen klaren Angemessenheitsmaßstab. |
| Grundlagen → Konzept | Die meisten Grundlagen werden später verwendet. Der LSM-/Kernelmodulvergleich enthält einen relevanten Sachfehler. |
| Konzept → Umsetzung | Architektur weitgehend wiedererkennbar; Scanparallelität und Konsistenzgarantien sind nicht deckungsgleich. |
| Umsetzung → Evaluation | Breite, sinnvoll ausgewählte Tests. Triggerabdeckung und finaler Nachweisstand bleiben lückenhaft. |
| Evaluation → Erfüllungsbewertung | Hauptbruch: differenzierte negative Ergebnisse münden trotzdem in pauschale funktionale Erfüllung. |
| Diskussion → Antwort | Fazit benennt wichtige Grenzen; neue Erkenntnisse zu Runtime, ptrace und Nachweisstand müssen aufgenommen werden. |

Es gibt keinen grundlegend verlorenen roten Faden. Das Problem liegt in wenigen, aber zentralen **Übergängen von beobachteter Funktion zu allgemeiner Eigenschaft**. Eine gemeinsame Tabelle „Anforderung – tatsächliche Funktion – Nachweis – Grenze – Erfüllungsgrad“ würde diesen Bruch wirksam schließen.

## 4. Wissenschaftliche Qualität

Die Sprache ist überwiegend sachlich und verständlich. Fachbegriffe werden eingeführt und in der Regel konsistent verwendet. Die Arbeit trennt mehrfach ausdrücklich zwischen Prototyp und vollständigem Kontrollsystem; das ist wissenschaftlich angemessen. Die technische Detailtiefe ist für den Abschluss mehr als ausreichend.

Die Quellenbasis ist überwiegend primär und geeignet. Alle 36 zitierten Einträge wurden im Quellen-Audit erfasst; Abrufhindernisse und nur teilweise geprüfte Aussagen sind dort ausgewiesen. Das falsche XACML-Jahr und einzelne bibliographische Fundstellen sollten bereinigt werden. Besonders positiv ist die präzise Belegung der Real-UID-Semantik durch versionierten Kernel- und Aya-Code.

Die größten wissenschaftlichen Schwächen sind keine Rechtschreibprobleme: Begriffe wie konsistenter Zustand, fortlaufende Aktualisierung und erfüllte Anforderung sind stärker als die vorliegende Herleitung. Literatur zur allgemeinen Plattform ersetzt keinen Nachweis dieser eigenen Eigenschaften.

Die Nachvollziehbarkeit wird durch fehlendes vollständiges Policy-/Attributbeispiel und Wiederholungen in der Konzeption beeinträchtigt. Ein kompaktes Beispiel einschließlich Default-Allow und fehlendem Deny-Attribut verbessert das Verständnis stärker als weitere abstrakte Architekturabsätze. Formale Hochschulvorgaben zu Deckblatt, Abstract oder Eigenständigkeitserklärung sind vor Abgabe anhand der tatsächlichen Vorgaben zu prüfen; mangels Vorgaben werden fehlende Elemente hier nicht als verbindlicher Verstoß behauptet.

## 5. Technische Qualität

Die acht Crates bilden eine nachvollziehbare Aufgabentrennung. Die feste Map-ABI, begrenzte Verarbeitung, gemeinsame semantische Funktionen und explizite Behandlung vorheriger BPF-LSM-Ablehnungen sind fachlich solide. Die Kapazitätsprüfung für Attributgenerationen berücksichtigt den gleichzeitigen Platzbedarf alter und neuer Zustände. Der Prototyp ist deutlich mehr als eine Demonstration eines einzelnen Hooks.

Die wesentlichen technischen Risiken liegen im Gesamtsystem:

- **Nebenläufigkeit:** Ein mehrthreadiger Tokio-Runtime-Typ erzeugt für direkt mit select! gepollte Zweige keine unabhängigen Tasks. Der synchrone Scan kann Loader und Zeitaktualisierung blockieren. [Tokio-Dokumentation](https://docs.rs/tokio/latest/tokio/macro.select.html)
- **Konsistenz:** Prepare-before-publish ist vorhanden. Die sichere Wiederverwendung einer Bank für beliebig lange Leser und mehrere Writer ist nicht nachgewiesen. Ein konkreter fehlerhafter Kernel-Interleaving wurde im Review nicht ausgeführt.
- **Lebenszyklus:** Ein fataler Runtimefehler kann den ungepinnten LSM-Link freigeben. Gepinnte Maps erhalten das Attachment nicht automatisch; andere Linux-Schutzmechanismen bleiben davon unberührt.
- **Revoker:** Das Patchen von Instruktionsspeicher, unzureichend differenzierte Stop-Zustände, fehlende Wartefrist und Cleanup-Grenzen betreffen Integrität und Fortschritt des Zielprozesses.
- **Semantik:** Default-Allow, fehlende Attribute und veränderliche Tasknamen begrenzen Sicherheitsinterpretationen. Sie müssen explizit von technischen Fail-closed-Fehlerpfaden unterschieden werden.

Für die Reference-Monitor-Argumentation ist die Vertrauensbasis größer als das kleine eBPF-Programm. Sie umfasst auch Loader, Eingaben, Maps, Uhr, Runtime und Revoker. Keine Tamper-Resistance gegenüber entsprechend privilegierter Administration wurde nachgewiesen. Complete Mediation kann nur im definierten Hook-Scope diskutiert werden. Das ist für einen Prototyp zulässig, muss aber als Betriebsannahme und Grenze kenntlich sein.

## 6. Evaluation

Die funktionale Abdeckung ist eine der stärksten Leistungen der Arbeit. Erlaubte und verweigerte Opens, Policy-/Attributsemantik, fehlerhafte Konfigurationen, Kapazitäten, UID-Varianten und problematische FD-Fälle werden untersucht. Negative Ergebnisse bleiben sichtbar. Es wäre unangemessen, wegen der verbleibenden Lücken von einer insgesamt fehlenden Evaluation zu sprechen.

Die Zahlen sind nachprüfbar: PERF-01 liefert Mediane von 3,845/4,389/4,412 µs; der relative Mehraufwand beträgt rund 14,1/14,7 %. Policy-/Attributaktivierung liegen bei etwa 102,41/103,34 ms, FD-Entzug bei 58,91 ms. Das sind **beobachtete Werte der jeweiligen Messfolge**, keine systemweiten Latenzgarantien.

Drei methodische Grenzen sind wesentlich:

1. Je 20.000 Opens in einem festen Messblock ersetzen keine unabhängigen Versuchswiederholungen. Ein weiterer archivierter Lauf zeigt spürbar andere relative Werte. Auswahl und Laufstreuung gehören in die Interpretation.
2. Die FD-Latenz unter der 100-ms-Bündelungszeit ist nicht automatisch falsch. Der Timerstart und mögliche bereits laufende inotify-Wartephasen erklären eine plausible Differenz; die konkrete Ursache wurde nicht durch vollständige Ereigniszeitstempel isoliert.
3. Policyänderungen sind als FD-Trigger belegt, reine Attributänderung und reiner Zeitablauf nicht jeweils als vollständiger realer Entzugspfad.

Die externe Validität bleibt auf die getestete VM-/Kernel-/Workloadkonfiguration begrenzt. Das ist ausdrücklich akzeptabel; ein umfassender Vergleich mit SELinux oder AppArmor ist keine notwendige Bacheloranforderung. Mehrere unabhängige Blöcke und ein Stream-Performancefall wären dennoch hilfreich.

Die Reproduzierbarkeit ist grundsätzlich angelegt, aber für eine Endfassung unvollständig geschlossen. Performance- und Funktionsnachweise stammen aus benannten historischen Ständen. Der aktuelle Produktionscode hat die dokumentierte Clippy-Strukturursache bereits verändert; ein neuer erfolgreicher Gesamtlauf ist nicht archiviert. Tatsächlich ausgeführte Toolchain-/Systemversionen und ein eindeutiger finaler Stand sollten ergänzt werden. Bestehende historische Ergebnisse behalten ihren Wert.

## 7. Bewertung der einzelnen Kapitel

| Kapitel | Bewertung | Größte Stärke | Größtes Problem | Handlungsbedarf |
|---|---|---|---|---|
| [1 Einleitung](Kapitel_01_Einleitung.md) | gut | Klare, angemessene Forschungsfrage | Scope muss mit korrigierter Erfüllungsbewertung konsistent bleiben | Gering; keine unnötige Neuformulierung |
| [2 Grundlagen](Kapitel_02_Grundlagen.md) | gut | Relevante Grundlagen und FD-Grenzen | Bibliographische Versionierung, Übertragung des Modells begrenzen | Mittel |
| [3 Anforderungsanalyse](Kapitel_03_Anforderungsanalyse.md) | solide, aber überarbeitungsbedürftig | Explizite Anforderungen und Prüfkriterien | FA-06/OA-03 zu stark bzw. nicht passend operationalisiert | Hoch |
| [4 Konzeption](Kapitel_04_Konzeption.md) | solide, aber überarbeitungsbedürftig | Plausible hybride Architektur | LSM-Vergleich und Konsistenzreichweite | Hoch |
| [5 Entwurf und Umsetzung](Kapitel_05_Entwurf_und_Umsetzung.md) | solide, aber überarbeitungsbedürftig | Substantielle technische Umsetzung | TODO, Scanparallelität, Lebenszyklus und ptrace | Sehr hoch |
| [6 Evaluation](Kapitel_06_Evaluation.md) | solide, aber überarbeitungsbedürftig | Breite Tests, offene negative Resultate, korrekte Zahlen | Erfüllungsgrad, Triggerbelege, finaler Stand | Hoch |
| [7 Zusammenfassung und Ausblick](Kapitel_07_Zusammenfassung_und_Ausblick.md) | gut | Tatsächliche Antwort und relevante Grenzen | Neue Befunde und veralteten Clippy-Status nachführen | Mittel |

## 8. Die wichtigsten Kritikpunkte der gesamten Thesis

Die IDs verweisen auf ausführliche Befunde in den jeweiligen Kapitelreviews oder im Code-Audit. Die folgende Verdichtung zählt kapitelübergreifende Wiederholungen nicht mehrfach.

| Priorität / ID | Problem | Konkrete empfohlene Lösung |
|---|---|---|
| **P0 F01** | Sichtbarer Diagramm-Platzhalter, S.39 | Echte aus Manifesten abgeleitete Abbildung einsetzen oder Abbildung mit Verweis entfernen; endgültige PDF visuell kontrollieren. |
| **P1 F02** | FA-06 trotz Best-effort-Fehlschlag als erfüllt bewertet | Unmittelbaren garantierten Entzug von beobachtetem Versuch trennen; FA-06 als teilweise erfüllt bewerten oder Ziel transparent begrenzen. |
| **P1 F03** | Klassisches LSM als ladbares Kernelmodul eingeordnet | Mainline-Kernelintegration und BPF-Laufzeit-Attach sachlich korrekt vergleichen. |
| **P1 F04** | Bankaktivierung als allgemeine Lesekonsistenzgarantie | Single-Writer-Annahme, Reader-Lebensdauer und Bankreuse explizit herleiten; unbelegte Garantie zurücknehmen. |
| **P1 F05** | Behauptete Updates während blockierendem Scan | Tatsächlichen gemeinsamen Task-Ablauf beschreiben; Entkopplung nur als getestete Weiterentwicklung, nicht als ungeprüften Schnellumbau. |
| **P1 F06** | Runtime-Ausfall/TCB unvollständig | Fehlerfortpflanzung, Link-Lebensdauer, Eingabe-/Map-/Uhrvertrauen und Schutzverlust erläutern. |
| **P1 F07** | Zwei dynamische FD-Trigger nicht separat E2E belegt | Reine Attributänderung und reine Zeitgrenze mit verletzendem und zulässigem FD testen; alternativ Evidenz ausdrücklich begrenzen. |
| **P1 F08** | Finaler Quell- und Nachweisstand nicht geschlossen | Finalen Linux-Prüflauf mit Stand/Exitcode/Umgebung archivieren; historische Resultate eindeutig zuordnen. |
| **P1 F14** | ptrace-Integritäts-/Fortschrittsrisiken unvollständig | Signal-/Thread-/Warte-/Cleanup-Grenzen im Ist-Zustand diskutieren; robuste Injektion als weiterführende Arbeit. |
| **P2 F09** | Latenz unter Bündelungszeit unzureichend erklärt | Timerstart/Ereignisphase benennen; optional Messung aus nachgewiesen ruhendem Zustand. |
| **P2 F10** | Einzellauf statt unabhängiger Wiederholungen | Zweiten Lauf einordnen; mehrere unabhängige Blöcke bzw. engere Gültigkeitsaussage. |
| **P2 F11** | XACML-Jahr/Fundstellen | Versionsgenaue Bibliographie und erreichbare Ersatzlinks. |
| **P2 F12** | Architekturabbildung ohne zentralen Aktivierungstrigger | Trigger-/Zeitpfad ergänzen oder Legende präzisieren; Abbildung/Tabelle im Text referenzieren. |
| **P2 F13** | Policywirkung schwer vollständig nachzuvollziehen | Ein durchgehendes Policy-/Attributbeispiel mit Default-Allow und fehlendem Attribut ergänzen. |
| **P2 F15** | OA-03 Angemessenheit ohne Maßstab | Als explorative Quantifizierung bewerten; keine nachträglich passend gewählte Erfolgsschwelle. |
| **P2 C01** | 16-Byte-Policyname versus 15 Nutzbytes in comm; Threadidentität | Grenzen dokumentieren; bei Codekorrektur 15/16-Byte-Fall testen und Semantik normalisieren. |
| **P2 C02** | Fehlgeschlagener Entzug ohne garantierten neuen Scan | Retry nur bei neuem Trigger ausdrücklich beschreiben; kontrollierte Retries als Future Work. |
| **P3 F16** | Wiederholungen in der Konzeption | Wiederholte Begründungen zusammenziehen; gewonnene Seiten für Beispiel und Sicherheitsannahmen nutzen. |

P0 bezeichnet hier einen eindeutigen formalen Abgabeblocker, keinen Zusammenbruch der wissenschaftlichen Substanz. Bei P1 ist häufig eine korrekte Einschränkung der Aussage ausreichend. P2/P3 sollen die Abgabe nicht durch unverhältnismäßige neue Entwicklung gefährden.

## 9. Die wichtigsten Stärken

- Angemessen schwieriges Betriebssystem-/Security-Thema mit erkennbarem eigenem Entwurfs- und Implementierungsanteil.
- Präzise Beschränkung auf Dateiöffnungen und nachvollziehbare hybride Architektur.
- Geteilte fachliche Auswertung zwischen Kernel und Userspace; feste Datenstrukturen und begrenzte Verarbeitung.
- Explizite Behandlung vorheriger LSM-Ablehnungen und sorgfältige Real-UID-Herleitung.
- Breite funktionale Tests einschließlich negativer Fälle und nachträglicher Korrektur eines real gefundenen Kapazitätsfehlers.
- Archivierte Rohdaten und rechnerisch korrekte Kennzahlen.
- Offene Benennung von mmap-, dup/fork- und TOCTTOU-Grenzen.
- Eine Schlussbetrachtung, die tatsächlich auf die Forschungsfrage zurückkommt.

## 10. Potenzielle Angriffspunkte eines Gutachters

| Frage | Warum naheliegend / Vorbereitung |
|---|---|
| Was ist hier ASBAC, wenn kein abonnierter SAPL-Decision-Stream existiert? | Ausgewählte Prinzipien und eigene Ereignis-/Map-Architektur klar abgrenzen. |
| Warum gerade file_open und was bleibt danach unkontrolliert? | Zugriffseröffnung und fortgesetzte Nutzung unterscheiden; mmap und andere FD-Pfade benennen. |
| Warum eBPF-LSM statt klassischem LSM? | Vergleich sachlich korrigieren und aus Prototyp-/Build-/Rust-Anforderungen ableiten. |
| Was garantiert ein Generationswechsel für einen noch laufenden Leser? | Publikation von Snapshot-Lebensdauer und Bankreuse unterscheiden; keine Testgarantie erfinden. |
| Laufen Loader wirklich während eines ptrace-Scans weiter? | Den direkten select!-Ablauf erklären und die aktuelle Blockierung einräumen. |
| Was passiert, wenn die Runtime beendet wird oder eine Policydatei nicht lesbar ist? | Map-Pins und Link-Lebensdauer unterscheiden; lokale Fail-closed-Pfade begrenzen. |
| Warum ist FA-06 erfüllt, obwohl E2E-17 einen Entzug verhindert? | Erfüllungsgrad vor Abgabe korrigieren. |
| Was bedeutet Deny-overrides bei fehlendem Attribut oder ausschließlich Permit-Policies? | Konkretes Beispiel und Default-Allow erläutern. |
| Warum liegt FD-Entzug unter 100 ms? | Messstart, Restereignisse und nicht isolierte Phase erklären. |
| Sind 20.000 Opens 20.000 unabhängige Versuche? | Innerhalb-/Zwischenlaufstreuung und feste Reihenfolge unterscheiden. |
| Wurde genau der abgegebene Stand vollständig getestet? | Eine Stand-zu-Artefakt-Tabelle und finalen Nachweis bereithalten. |
| Kann ptrace einen fremden Thread beschädigen oder unbegrenzt warten? | Integritäts-/Fortschrittsgrenzen anerkennen; Best effort ist keine Sicherheitsgarantie. |

## 11. Risiken für die Benotung

| Problemgruppe | Potenzieller Einfluss | Konkrete Abhilfe |
|---|---|---|
| Anforderungs-/Ergebniswiderspruch F02 | Hoch; betrifft wissenschaftliche Schlussfolgerung | Erfüllungsgrad und Fazit konsistent begrenzen |
| Beschreibung versus Code F04–F06 | Hoch; Zweifel an Verständnis der eigenen Architektur | Präziser Ist-Ablauf und nachvollziehbare Sicherheitsannahmen |
| Fehlende dynamische Integrationsbelege/finaler Stand F07/F08 | Mittel bis hoch; begrenzt Belastbarkeit | Zwei gezielte Szenarien und finaler dokumentierter Lauf |
| ptrace-Risiken F14 | Mittel bis hoch; technische Limitation zu eng diskutiert | Integritäts-/Fortschrittsgrenzen offen darstellen |
| TODO F01 | Sichtbarer Vertrauensverlust in Sorgfalt; leicht behebbar | Endgültige Grafik/PDF prüfen |
| Performance-/Quellen-/Beispielpräzision | Mittel bzw. gering; verhindert eher sehr gute Bewertung | Reichweite präzisieren, zentrale Einträge und Beispiel ergänzen |
| Wiederholungen/Stil | Gering | Erst nach sachlichen Korrekturen kürzen |

Die Gruppen überschneiden sich; daraus wird kein schematischer mehrfacher Notenabzug berechnet. Insbesondere hängen F02, F07 und F14 am selben Thema der nachträglichen Kontrolle.

## 12. Priorisierter finaler Überarbeitungsplan

**Vor Abgabe zwingend**

1. Platzhalter auf S.39 ersetzen oder sauber entfernen; finale PDF einschließlich Verweisen kontrollieren. Aufwand gering bis mittel.
2. FA-06 und §6.3.4 mit Best effort/E2E-17 abgleichen. In Kapitel 7 denselben Erfüllungsgrad verwenden. Aufwand mittel.
3. Aussage zu weiterlaufenden Updates während Scans an den direkten select!-Ablauf anpassen. Zeitfrische und blockierendes Warten als Grenze nennen. Aufwand mittel.
4. LSM-/Kernelmodulvergleich berichtigen und die Konsistenzgarantie auf das tatsächlich hergeleitete Writer-/Reader-Modell beschränken. Aufwand mittel bis hoch.

**Vor Abgabe dringend empfohlen**

5. Einen kompakten Abschnitt zum tatsächlichen Vertrauensmodell, Runtime-Ausfall und ptrace-Integritäts-/Fortschrittsgrenzen ergänzen; C01/C02 mitführen. Aufwand mittel bis hoch.
6. Auf dem Zielsystem zwei reale Entzugsszenarien für Attributänderung und Zeitablauf ergänzen. Falls dies nicht möglich ist, fehlenden Integrationsnachweis ausdrücklich markieren. Aufwand hoch für Tests, gering bis mittel für transparente Begrenzung.
7. Abgabestand eindeutig festlegen, zentrale Linux-Prüfkette ausführen und Stand, Dirty-Status, Exitcode sowie tatsächliche Versionen archivieren. Clippy-Aussage aktualisieren, historische Rohdaten erhalten. Aufwand hoch bei verfügbarem Zielsystem.
8. PERF-03-Messstart/Ereignisphase und PERF-01-Einzellaufcharakter erklären; vorhandenen zweiten Lauf einordnen. OA-03 entsprechend präzisieren. Aufwand mittel.
9. XACML-Eintrag korrigieren und ein vollständiges Policy-/Attributbeispiel ergänzen. Aufwand mittel.

**Falls noch Zeit vorhanden**

10. Unabhängige Performanceblöcke mit wechselnder Reihenfolge und einem Stream-Fall messen; Ergebnisreichweite entsprechend erweitern.
11. Aktivierungstrigger in der Architekturabbildung ergänzen, Textverweise schließen und konzeptionelle Wiederholungen reduzieren.
12. Abschließende lokale Formvorgaben, Titel-/Literaturdarstellung und PDF-Satz kontrollieren.

Die Zeitkategorien bezeichnen einzelne Arbeitspakete; Zielsystemverfügbarkeit und neue Fehler können den Aufwand erhöhen. Kein umfangreicher Umbau von Parallelität, Snapshotverwaltung oder ptrace unmittelbar vor Abgabe ohne neue Validierung. Eine wissenschaftlich genaue Einschränkung ist eine echte Verbesserung und keine bloße Ausrede.

## 13. Hypothetisches Gutachten

Die vorliegende Bachelorarbeit untersucht die prototypische Umsetzung attributstrombasierter Zugriffskontrolle für Dateiöffnungen unter Linux mittels eBPF-LSM. Das Thema weist für eine Bachelorarbeit einen hohen technischen Anspruch auf, da Sicherheitskonzepte, Kernelprogrammierung und die nachträgliche Kontrolle bestehender Betriebssystemressourcen zusammengeführt werden.

Die Verfasserleistung ist in der Konzeption einer hybriden Architektur und deren Umsetzung in einem modularen Rust-/Aya-System deutlich erkennbar. Die Arbeit verfügt über eine weitgehend angemessene theoretische Fundierung und nutzt überwiegend geeignete Primärquellen. Besonders positiv sind die gemeinsame fachliche Auswertungslogik, die bewusste Begrenzung des Kernelanteils und die detaillierte Behandlung von UID- und FD-Semantik.

Die Evaluation geht über reine Positivbeispiele hinaus. Sie umfasst funktionale, quantitative und charakterisierende Experimente und dokumentiert auch fehlgeschlagene Versuche sowie Grenzen des Ansatzes. Die berichteten Messwerte sind anhand der vorhandenen Daten nachvollziehbar. Die Diskussion von Mappings und FD-Races zeigt ein grundsätzlich vorhandenes Verständnis der Einschränkungen.

Dem stehen relevante Schwächen in der abschließenden wissenschaftlichen Einordnung gegenüber. Die vollständige Erfüllung des nachträglichen Entzugs wird stärker bewertet, als Implementierung und negative Testergebnisse erlauben. Einzelne Aussagen zur Nebenläufigkeit stimmen mit der tatsächlichen Steuerung nicht überein. Die Konsistenzargumentation und die Betrachtung des Runtime-Ausfalls bleiben unvollständig. Für zwei zentrale dynamische Entzugspfade fehlen gesonderte Integrationsnachweise; die finale Prüfstandzuordnung ist nicht vollständig abgeschlossen. Die Performanceuntersuchung erlaubt eine begrenzte Charakterisierung, jedoch keine robuste Verallgemeinerung. Ein sichtbarer Abbildungsplatzhalter beeinträchtigt zusätzlich den Eindruck einer sorgfältig abgeschlossenen Fassung.

Insgesamt liegt eine technisch anspruchsvolle und substanzielle Arbeit mit überwiegend guter fachlicher Grundlage vor. Sie beantwortet die Forschungsfrage im Wesentlichen, erreicht aber aufgrund der genannten Widersprüche und Nachweisgrenzen nicht durchgehend die Präzision einer sehr guten Abschlussarbeit. Unter angemessener Gewichtung des Bachelor-Niveaus wird die Leistung insgesamt mit **gut (2,3)** bewertet.

## 14. Abschließende Note

**Realistische Gesamtnote in der aktuellen Fassung: 2,3**

**Plausibler Notenkorridor: 2,0–2,7**

Die Bewertung mit 2,3 gewichtet die erhebliche technische Eigenleistung, die breite funktionale Evaluation und die offenen Limitationen positiv. Die Arbeit ist weder oberflächlich noch überwiegend unbelegt. Deshalb wäre eine deutlich schlechtere Note allein wegen prototypischer Grenzen unangemessen.

Eine Bewertung im sehr guten Bereich ist gegenwärtig nicht überzeugend: Die unzutreffende Parallelitätsbeschreibung, die pauschale FA-Erfüllung, die fehlende Lebenszyklusbilanz und die unvollständig geschlossene Evidenz betreffen zentrale Aussagen. Der sichtbare Platzhalter ist zusätzlich ein vermeidbarer Sorgfaltsmangel. Diese Probleme lassen sich nicht als bloßer sprachlicher Feinschliff abtun.

Ein Prüfer mit stärkerer Gewichtung von Implementierungsumfang und transparenter experimenteller Arbeit könnte 2,0 vertreten. Ein stärker auf Sicherheitsherleitung, Reproduzierbarkeit und stringente Anforderungserfüllung fokussierter Prüfer könnte 2,7 vergeben. Die 2,3 ist eine Gesamtabwägung, kein arithmetisches Mittel fiktiver Teilnoten und keine Vorhersage einer verbindlichen Hochschulentscheidung.

## 15. Potenzial nach den letzten Korrekturen

**Realistisch erreichbare Note nach Umsetzung der empfohlenen Korrekturen: 1,7**

Dafür sollten die zentralen Beschreibungen und Erfüllungsurteile sachlich korrigiert, das tatsächliche Vertrauens-/Lebenszyklusmodell ergänzt und die wesentlichen dynamischen Integrationspfade sowie der finale Prüfstand nachvollziehbar belegt werden. Eine präzisere Messinterpretation und das vollständige Policybeispiel würden die wissenschaftliche Nachvollziehbarkeit weiter stärken.

Ohne neue Tests kann die Arbeit durch ehrliche Begrenzung und klare Argumentation bereits erheblich gewinnen; dann ist eher eine gefestigte **2,0** als eine sichere 1,7 zu erwarten. Reine Kosmetik — Diagramm ersetzen, Tippfehler bereinigen, Bib-Titel formatieren — verbessert die Abgabesorgfalt, schließt aber die zentralen Begründungs- und Evidenzlücken nicht.

Eine 1,0 oder 1,3 wird nach bloßen Abschlusskorrekturen nicht versprochen. Dafür müssten insbesondere Konsistenz, Robustheit und experimentelle Aussagekraft noch überzeugender abgesichert sein. Das ist für einen erfolgreichen Bachelorabschluss nicht erforderlich.


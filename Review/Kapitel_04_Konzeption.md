# Review Kapitel 4 – Konzeption

Stand: 11.09.2026. Begutachtet: aktueller Arbeitsbaum und vorhandene PDF, S. 19–36. Seitenangaben beziehen sich auf die gedruckten Seitenzahlen der 75-seitigen PDF. F-IDs sind reviewweit eindeutig; Querverweise bezeichnen denselben Befund und keine zusätzlichen Mängel.

## 1. Aufgabe des Kapitels

Die Architektur muss aus den Anforderungen begründet werden. Daten- und Kontrollfluss, Alternativen, Entscheidungskonsequenzen und Sicherheitsannahmen sollen die eigene Entwurfsleistung nachvollziehbar machen.

## 2. Gesamteindruck

**solide, aber überarbeitungsbedürftig.** Es liegt ein umfangreicher, grundsätzlich schlüssiger Entwurf vor. Die Begründung der hybriden Aufteilung ist überzeugend. Schwächer sind der Vergleich mit klassischem LSM, die zu starke Konsistenzsprache und die im Diagramm fehlende Ereignissteuerung.

## 3. Stärken

- Die Entwurfsentscheidungen nennen meist Problem, Lösung, Alternative und Konsequenz.
- Device/Inode statt Pfadstrings wird nachvollziehbar begründet; Dateiersetzung wird als Grenze erkannt.
- Die feste Repräsentation, zwei Banken und getrennte statische/Stream-Stufen passen zu den eBPF-Beschränkungen.
- Best-Effort-FD-Enforcement wird einschließlich mmap und laufender E/A begrenzt; diese Einschränkungen werden nicht verschwiegen.

## 4. Kritikpunkte

### F03 – Kritikpunkt: Klassisches LSM mit ladbarem Kernelmodul verwechselt

**Fundstelle:** §4.6.2, PDF S.26, thesis/sections/04-konzeption.tex:284.

**Priorität:** P1.

**Kategorie:** Technische Korrektheit; Quelle; Technologieentscheidung.

**Problem:** „Ein klassisches LSM ist Teil des Kernelcodes oder wird als Kernelmodul entwickelt“ beschreibt die übliche Mainline-LSM-Integration irreführend als regulär nachladbares Modul. Die bereits zitierte Linux-Security-Module-Usage-Dokumentation erklärt ausdrücklich, dass diese LSM-Erweiterungen keine ladbaren Kernelmodule sind.

**Warum ist das problematisch?** Gerade der Vergleich mit eBPF-LSM muss die Integrations- und Ladebedingungen korrekt unterscheiden. Das historische LSM-Paper von 2002 ersetzt hier keine Beschreibung des Zielkernels.

**Auswirkungen:** Fachlicher Fehler in einer zentralen Technologiebegründung; die Wahl von eBPF-LSM bleibt dennoch plausibel.

**Lösung A – empfohlen:** Mit einem klassischen, in den Kernel integrierten LSM vergleichen: Kernelintegration/Build/Boot gegenüber BPF-LSM-Laufzeitanbindung, Verifiergrenzen und gemeinsamer Rust-Codebasis; Versionsbezug nennen.

**Lösung B – Alternative:** Falls ausdrücklich ein experimentelles Out-of-tree-Modulsystem gemeint ist, dieses konkret benennen, belegen und vom üblichen LSM-Mechanismus abgrenzen.

**Empfehlung des Gutachters:** A; direkt durch [Linux Security Module Usage](https://docs.kernel.org/admin-guide/LSM/index.html) überprüfbar.

**Aufwand:** gering: < 30 Minuten.

**Erwarteter Nutzen:** hoch.

**Relevanz für die Benotung:** mittel: zentraler Sachfehler, aber lokal gut reparierbar.

### F04 – Kritikpunkt: Generationenumschaltung wird mit stabiler Lesesicht gleichgesetzt

**Fundstelle:** §4.3.1, S.20–21; §4.6.7, S.29–30; §5.4.5, S.46; 04-konzeption.tex:97,414; policy_source.rs:243; file_open_static_policies.rs:13; file_open_stream_policies.rs:152.

**Priorität:** P1.

**Kategorie:** Nebenläufigkeit; Security; Thesis-vs.-Code.

**Problem:** Vorbereitung vor Veröffentlichung ist implementiert. Es gibt aber nur zwei wiederverwendete Bänke und keinen Leserzähler, keine Wartefrist auf abgeschlossene Leser und keine abschließende Generationsvalidierung. Ein gespeicherter Generationswert verhindert nicht, dass seine inzwischen inaktive Bank später überschrieben wird. Mehrere Runtime-Instanzen werden im Hauptprogramm ebenfalls nicht gesperrt. Die Aussage, teilweise aktualisierte Mengen würden verhindert, ist daher als allgemeine Garantie nicht belegt.

**Warum ist das problematisch?** Publikationsreihenfolge und Lebensdauer eines gelesenen Zustands sind verschiedene Eigenschaften. Die Unit-Tests prüfen Schreibreihenfolge und Fehlerrollback, nicht beliebige nebenläufige Leser. Ein konkreter fehlerhafter Kernelentscheid wurde in diesem Review nicht reproduziert.

**Auswirkungen:** Zu starke Konsistenzbehauptung; insbesondere bei Mehrschreiberbetrieb oder künftig wirklich parallelen Scans relevant. Policy- und Attributgeneration bilden außerdem keine gemeinsame Transaktion.

**Lösung A – empfohlen:** Garantie auf erfolgreiches Vorbereiten vor Aktivierung und den getesteten Ein-Schreiber-Betrieb begrenzen; Leserlebensdauer, unabhängige Generationen und fehlenden Nebenläufigkeitsnachweis ausdrücklich diskutieren.

**Lösung B – Alternative:** Leserprotokoll beziehungsweise unveränderliche Snapshots mit gesicherter Lebensdauer entwerfen und durch gezielte Interleaving-Tests nachweisen. Ein bloßes drittes Array oder eine Wartezeit ohne Begründung genügt nicht.

**Empfehlung des Gutachters:** A vor Abgabe. B wäre eine eigene technische Weiterentwicklung. Achtung: Im aktuellen Hauptprozess blockiert ein synchroner Scan die Loader; gerade deshalb ist die in §5.7.1 behauptete interne Aktivierung während dieses Scans nicht der tatsächliche Ablauf (F05).

**Aufwand:** mittel: 30 Minuten bis 2 Stunden für A; sehr hoch: > 8 Stunden für B.

**Erwarteter Nutzen:** hoch.

**Relevanz für die Benotung:** hoch: begrenzt eine zentrale Architekturzusicherung.

### F12 – Kritikpunkt: Architekturabbildung zeigt den zentralen Aktivierungstrigger nicht

**Fundstelle:** §4.2, PDF S.21, Abbildung 1; 04-konzeption.tex:75; graphics/architecture.jpg; §6.3.1 Tabelle 7.

**Priorität:** P2.

**Kategorie:** Abbildung/Tabelle; Struktur.

**Problem:** Die Architekturübersicht zeigt Zustandszugriffe und FD-Enforcement, aber keine Aktivierungsereignisse von Policy-/Attributloader zum Userspace-PEP und keinen Zeitgrenzentrigger. Gerade dies unterscheidet den Ansatz von einem periodischen Scan. Abbildung 1 hat außerdem keinen expliziten ref-Verweis im Fließtext; auch die Zusammenfassungstabelle der funktionalen Resultate ist nicht explizit referenziert.

**Warum ist das problematisch?** Die Übersicht bildet die entscheidende Steuerung nur unvollständig ab. Die pauschale Logging-Box kann außerdem einen zentralen Log-Kanal nahelegen, den es so nicht gibt.

**Auswirkungen:** Begrenzte visuelle Nachvollziehbarkeit, obwohl der Text den Ereignispfad erklärt.

**Lösung A – empfohlen:** Triggerpfeile mit Legende ergänzen, Best-Effort-Entzug und getrennte optionale Logs kenntlich machen; beide Objekte im Fließtext ausdrücklich referenzieren und erklären.

**Lösung B – Alternative:** Abbildung ausdrücklich als reine Zustands-/Durchsetzungsübersicht kennzeichnen und den nicht dargestellten Steuerpfad direkt daneben erläutern.

**Empfehlung des Gutachters:** A; nach Export eingebundene Grafik kontrollieren, damit F01 nicht wiederholt wird.

**Aufwand:** mittel: 30 Minuten bis 2 Stunden.

**Erwarteter Nutzen:** mittel.

**Relevanz für die Benotung:** gering bis mittel: bessere Vermittlung der eigenen Architektur.

### F16 – Kritikpunkt: Konzeption wiederholt dieselbe Begründung zu häufig

**Fundstelle:** §4.1–4.6, PDF S.19–36; Wiederholungen zu Userspace-Parsing, festem Layout und kleinem Kernelanteil.

**Priorität:** P3.

**Kategorie:** Struktur; Sprache.

**Problem:** Architektur, Datenfluss, Komponenten, Datenobjekte und mehrere Entwurfsentscheidungen erläutern wiederholt, dass komplexes Parsing im Userspace und kompakte Auswertung im Kernel stattfinden. Einige Alternativen bleiben dabei asymmetrisch knapp, beispielsweise socket_bind statt der für fortdauernde Dateinutzung näherliegenden zusätzlichen Datei-Hooks.

**Warum ist das problematisch?** Umfang ersetzt keine zusätzliche Begründung; die langen Wiederholungen verdecken einzelne wirklich relevante Entscheidungen.

**Auswirkungen:** Lesefluss und Gewichtung, keine Gefährdung der wissenschaftlichen Korrektheit.

**Lösung A – empfohlen:** Wiederholungen durch präzise Querverweise ersetzen und eine kurze Entscheidungsmatrix anhand FA/OA/EA verwenden; Raum für Vertrauens- und Konsistenzmodell nutzen.

**Lösung B – Alternative:** Nur die mehrfachen Schlussabsätze kürzen, um vor Abgabe das Layout stabil zu halten.

**Empfehlung des Gutachters:** B bei knapper Zeit, A bei geplanter größerer Überarbeitung.

**Aufwand:** mittel: 30 Minuten bis 2 Stunden.

**Erwarteter Nutzen:** mittel.

**Relevanz für die Benotung:** gering: überwiegend Darstellung.


**Kapitelübergreifende Befunde:** F06 verlangt ein explizites heutiges Vertrauensmodell. F13 erläutert die sicherheitstechnische Konsequenz der gewählten Standardentscheidung. Beide Punkte werden im Implementierungsreview vollständig beschrieben.

## 5. Fehlende Inhalte

Ein kompakter TCB-/Bedrohungsmodell-Abschnitt und eine Zustands-/Fehlertabelle fehlen. Für Bankkonsistenz sollte eine Invariante samt Voraussetzungen angegeben werden. Ein zusätzlicher Datei-Hook als Alternative zur nachträglichen Revocation verdient eine kurze Einordnung; eine vollständige Neuimplementierung ist nicht nötig.

## 6. Überflüssige oder redundante Inhalte

Die wiederkehrende Userspace-/Kernel-Begründung ist der auffälligste redaktionelle Schwachpunkt (F16). Die starke Untergliederung macht das Inhaltsverzeichnis lang, ist aber kein eigenständiger Abgabemangel.

## 7. Quellen und Belege

Der eBPF-LSM-Mechanismus und die historische Hook-Idee sind gedeckt. Aktuelle Mainline-LSM-Ladebedingungen dürfen nicht aus dem historischen Paper abgeleitet werden. XACML ist ausdrücklich nur terminologischer Bezug; keine falsche Behauptung vollständiger XACML-Implementierung.

## 8. Bezug zum Quellcode

Bankoffsets, Maps, Deny-Vorrang und Tail-Call-Kette sind vorhanden. Atomare Veröffentlichung darf nicht mit einer allgemeinen Snapshot-Garantie verwechselt werden. Mehrere zukünftige Hooks werden als Erweiterung, nicht als vorhanden dargestellt.

## 9. Beitrag zur Forschungsfrage

Die hybride Architektur ist die zentrale konstruktive Antwort auf den ersten Teil der Forschungsfrage. Ihre konsequente Begrenzung beantwortet zugleich den zweiten Teil.

## 10. Wichtigste Maßnahmen

1. LSM-Vergleich berichtigen (F03).
2. Konsistenzbehauptung auf nachgewiesene Invarianten begrenzen (F04).
3. Vertrauensmodell/Lebenszyklus aufnehmen (F06).
4. Aktivierungstrigger in Abbildung 1 sichtbar machen (F12).
5. Erst danach Wiederholungen kürzen (F16).


# Review Kapitel 5 – Entwurf und Umsetzung

Stand: 11.09.2026. Begutachtet: aktueller Arbeitsbaum und vorhandene PDF, S. 37–55. Seitenangaben beziehen sich auf die gedruckten Seitenzahlen der 75-seitigen PDF. F-IDs sind reviewweit eindeutig; Querverweise bezeichnen denselben Befund und keine zusätzlichen Mängel.

## 1. Aufgabe des Kapitels

Die Implementierung muss die konzeptionellen Entscheidungen durch konkrete Strukturen und Abläufe belegen. Wissenschaftlich entscheidend sind richtige Laufzeitsemantik, nachvollziehbare Grenzen und Übereinstimmung mit dem eingereichten Code.

## 2. Gesamteindruck

**solide, aber überarbeitungsbedürftig.** Das Kapitel zeigt beträchtliche technische Eigenleistung und stimmt in vielen Einzelheiten mit dem Code überein. Ein sichtbarer Grafikplatzhalter sowie die falsche Parallelitätsvorstellung und unvollständige Ausfallbilanz verhindern jedoch ein abschließendes „gut“ in der jetzigen Fassung.

## 3. Stärken

- Acht Crates mit klaren Rollen; gemeinsame Typen und Auswertungsfunktionen reduzieren semantische Abweichungen.
- Policy- und Attributvalidierung sowie Aktivierung nach vollständigem Schreiben sind konkret beschrieben und implementiert.
- Die Real UID wird ausdrücklich gewählt und durch einen eigenen E2E-Fall von Effective-/Filesystem-UID abgegrenzt.
- Frühere BPF-LSM-Ablehnung und fehlgeschlagene Tail Calls werden fail-closed behandelt.
- Map-Kapazitätsfehler werden vor Mutation zurückgewiesen; der Fehlerbehebung liegen reale Nachtests zugrunde.

## 4. Kritikpunkte

### F01 – Kritikpunkt: Platzhalter statt Abhängigkeitsdiagramm

**Fundstelle:** §5.1.2, PDF S.39, Abbildung 2; thesis/sections/05-entwurf-und-umsetzung.tex:69; thesis/graphics/abhaengigkeiten.jpg.

**Priorität:** P0.

**Kategorie:** Abbildung/Tabelle; Abgabereife.

**Problem:** Die tatsächlich eingebundene JPG-Datei und die gerenderte PDF-Seite zeigen „TODO abhaengigkeiten Diagram,“ statt der angekündigten Crate-Struktur. Die editierbare Drawio-Datei ersetzt die im PDF sichtbare Grafik nicht.

**Warum ist das problematisch?** Ein ausdrücklich angekündigter Bestandteil ist offensichtlich unfertig. Das beschädigt den Eindruck einer abgeschlossenen Arbeit, auch wenn die Abhängigkeiten im Fließtext weitgehend richtig sind.

**Auswirkungen:** Formaler Abgabeblocker; kein Beleg für ein Scheitern der technischen Eigenleistung.

**Lösung A – empfohlen:** Die vorhandene Abhängigkeitsbeschreibung mit den Cargo.toml-Dateien abgleichen, eine echte Grafik exportieren und genau deren Einbindung im endgültigen PDF prüfen.

**Lösung B – Alternative:** Abbildung samt Verweis entfernen, sofern die vorhandene Aufzählung die Abhängigkeiten ausreichend erklärt.

**Empfehlung des Gutachters:** A, weil eine kompakte Architekturübersicht hier tatsächlich hilfreich ist; B ist bei Zeitdruck wissenschaftlich vertretbar.

**Aufwand:** mittel: 30 Minuten bis 2 Stunden.

**Erwarteter Nutzen:** sehr hoch.

**Relevanz für die Benotung:** hoch: ein sichtbares TODO ist für einen Abschlussgutachter unmittelbar negativ.

### F05 – Kritikpunkt: Synchrone Scans blockieren sämtliche select!-Zweige

**Fundstelle:** §5.3.3, S.43–44; §5.7.1, S.51–52; tails-pdp/src/main.rs:130; tails-pdp-userspace-pep/src/pep.rs:134,163; fd_revoker.rs:212.

**Priorität:** P1.

**Kategorie:** Thesis-vs.-Code; Robustheit; Zeitverhalten.

**Problem:** Die vier Futures werden direkt in einem tokio::select! desselben Tasks gepollt. run_scan enthält synchrone /proc-Lesezugriffe, Policy-Lookups und ptrace mit blockierendem waitpid(...,0). Während dieses Abschnitts können Zeit- und Attributupdater sowie Policywatcher nicht weiterlaufen. Ein Multithread-Tokio-Runtime-Attribut macht diese Zweige nicht parallel. Die Beschreibung fortlaufender Zeitupdates und gleichzeitig aktivierter Zustände während eines Scans ist deshalb unzutreffend.

**Warum ist das problematisch?** Die offizielle [Tokio-select!-Dokumentation](https://docs.rs/tokio/latest/tokio/macro.select.html) bestätigt dieses Laufzeitmodell. Ein langer oder hängenbleibender Scan betrifft dadurch auch die Frische der Kernelentscheidungsgrundlagen.

**Auswirkungen:** Relevante Robustheitsgrenze der hybriden Architektur. E2E-17 testet einen sofort gemeldeten Attach-Konflikt, kein dauerhaft blockierendes Warten.

**Lösung A – empfohlen:** Ist-Zustand korrekt beschreiben, seriell blockierende Abschnitte und fehlende harte Obergrenze nennen; einen langsamen/gestoppten Zielprozess als fehlenden Test ausweisen.

**Lösung B – Alternative:** Scan und ptrace in einen kontrollierten Worker mit begrenzter Ausführungszeit auslagern; dabei konsistente Snapshots, ptrace-Threadzugehörigkeit, Abbruch und Cleanup explizit entwerfen und testen.

**Empfehlung des Gutachters:** A als zwingende Textkorrektur, B nur mit ausreichender Testzeit. Kein ungetestetes spawn_blocking-Refactoring unmittelbar vor Abgabe.

**Aufwand:** mittel: 30 Minuten bis 2 Stunden für A; hoch bis sehr hoch für B.

**Erwarteter Nutzen:** sehr hoch.

**Relevanz für die Benotung:** hoch: die behauptete Laufzeitarchitektur ist eine Kernleistung.

### F06 – Kritikpunkt: Ausfall der Runtime und Vertrauensmodell fehlen in der Sicherheitsbilanz

**Fundstelle:** §5.3.3, S.43–44; §5.9.3, S.54–55; §7.2–7.3; tails-pdp/src/main.rs:42,116,130; policy_source.rs:161; Aya b93ee8c programs/links.rs:108,256,313.

**Priorität:** P1.

**Kategorie:** Security; Lebenszyklus; Reference Monitor.

**Problem:** Der LSM-Link wird an das lokale Aya-Objekt gebunden und nicht gepinnt. Ein fataler select!-Fehler oder Prozessende lässt den eigenen Hook verschwinden; gepinnte Maps halten dessen Attachment nicht aufrecht. Beispielsweise wird ein Lesefehler beim Einlesen der Policy-Dokumente in sync_if_changed mit ? weitergegeben, während Parser-/Commitfehler behandelt werden. Kapitel 7 nennt Rechtehärtung als Zukunftsarbeit, formuliert aber kein geschlossenes heutiges Vertrauensmodell.

**Warum ist das problematisch?** Fail-closed im noch laufenden Hook ist keine Aussage über Schutz nach dessen Entfernung. Ein Prüfer muss wissen, wem Dateien, Maps, Loader, Uhrzeit, Kernel und ptrace-Rechte anvertraut werden. Andere LSMs/DAC bleiben natürlich wirksam.

**Auswirkungen:** Unvollständige Sicherheitsinterpretation; kein Anspruch auf Schutz gegen privilegierte Administratoren ableitbar.

**Lösung A – empfohlen:** Eine kurze TCB-/Bedrohungsmodell-Tabelle plus Lebenszyklustabelle ergänzen: vertrauenswürdiger Administrator und Eingabequellen, ein Loader, unprivilegierte Zielprozesse, kein Schutz gegen Kernel-/BPF-Administration; bei Runtime-Ausfall entfällt diese zusätzliche Kontrolle. Fatalen Policy-Lesefehler getrennt benennen.

**Lösung B – Alternative:** Für stärkeren Schutz gepinntes Attachment, Überwachung und definierte Stale-State-/Recovery-Strategie entwerfen; das bloße Pinning des Links löst veraltete Attribute und Tail-Call-Lebensdauer nicht allein.

**Empfehlung des Gutachters:** A reicht für einen ehrlich begrenzten Bachelorprototyp; B ist überwiegend Future Work.

**Aufwand:** mittel: 30 Minuten bis 2 Stunden.

**Erwarteter Nutzen:** sehr hoch.

**Relevanz für die Benotung:** hoch: betrifft tamper resistance und Schutzverfügbarkeit.

### F13 – Kritikpunkt: Policy-Semantik ohne vollständiges Beispiel schwer prüfbar

**Fundstelle:** §5.4, PDF S.44–46; §4.6.11, S.32–33; common/src/lib.rs:776,913; ebpf/.../file_open_stream_policies.rs:136.

**Priorität:** P2.

**Kategorie:** Darstellung; Policy-Semantik; Security.

**Problem:** Die Sprache wird ausführlich in Prosa beschrieben, aber die Thesis zeigt kein vollständiges Policy-Dokument mit Attributdatei und resultierenden Entscheidungen. Die Default-Allow-Regel und die Nichtanwendbarkeit bei fehlendem Attribut sind technisch klar dokumentiert, ihre Kombination wird aber nicht an einem Beispiel diskutiert: Eine alleinige Permit-Bedingung beschränkt nichts; verschwindet das Attribut einer Deny-Policy, kann der Zugriff erlaubt werden. „Fehlende Map-Werte führen zur Ablehnung“ in §5.9.3 ist dafür zu pauschal.

**Warum ist das problematisch?** Bei einer Zugriffskontrollarbeit ist die tatsächlich erzielbare Policy-Wirkung zentral. Es wäre falsch, den implementierten Umgang mit fehlenden Attributen nachträglich als versehentlichen Codebug zu behandeln; er wird sogar in E2E-12 getestet.

**Auswirkungen:** Risiko eines falschen Leserverständnisses der Ausdrucksstärke und der Grenze des technischen Fail-closed.

**Lösung A – empfohlen:** Ein kurzes vollständiges Deny-/Attributbeispiel plus Entscheidungstabelle für wahr/falsch/fehlend/typfalsch und Permit-only ergänzen; Kontrollmap-Fehler von fachlich fehlenden Attributen unterscheiden.

**Lösung B – Alternative:** Eine präzise Semantiktabelle ohne Listing ergänzen und auf ein konkretes eingereichtes Beispieldokument verweisen.

**Empfehlung des Gutachters:** A; ein einziges gutes Beispiel ist wertvoller als weitere Parserprosa.

**Aufwand:** mittel: 30 Minuten bis 2 Stunden.

**Erwarteter Nutzen:** hoch.

**Relevanz für die Benotung:** mittel: verbessert fachliche Prüfbarkeit unmittelbar.

### F14 – Kritikpunkt: ptrace-Risiken betreffen auch Integrität und Fortschritt des Zielprozesses

**Fundstelle:** §5.7.3, PDF S.52–53; §7.2, S.71; fd_revoker.rs:39,48,68,212.

**Priorität:** P1.

**Kategorie:** Security; Robustheit; Implementierungsqualität.

**Problem:** Die Arbeit diskutiert FD-TOCTTOU gut. Zusätzlich patcht der Revoker jedoch Instruktionen im Adressraum, stoppt nur die adressierte Task und akzeptiert in wait_stopped jeden WIFSTOPPED-Status ohne Prüfung des erwarteten Stoppsignals. Das waitpid ist ohne Timeout. Schlägt das Warten nach erfolgreichem Attach fehl, existiert der RAII-Guard noch nicht; Wiederherstellungs-/Detachfehler sind ebenfalls nicht vollständig absichernd behandelt. Andere Threads desselben Adressraums werden nicht gemeinsam angehalten.

**Warum ist das problematisch?** Ein Angriff oder Fehler kann hier über einen bloß erfolglosen FD-Entzug hinausgehen. Dass ein normaler Testprozess nachher den sicheren FD behält, belegt keine allgemeine Erhaltung von Signal- und Threadverhalten. Kein solcher Schaden wurde im Review dynamisch provoziert.

**Auswirkungen:** Wesentliche, bisher zu knapp behandelte Grenze des invasiven Enforcement. Die [ptrace-Manpage](https://man7.org/linux/man-pages/man2/ptrace.2.html) belegt Task-Bezug und differenzierte Stopzustände.

**Lösung A – empfohlen:** Die Grenzen explizit in Implementierung und Diskussion aufnehmen; kooperative/einfache Zielprozesse als nachgewiesenen Testbereich nennen. Fehlerpfade nach Attach, Signalunterbrechungen und Mehrthreadzugriffe als gesonderte Tests vorsehen.

**Lösung B – Alternative:** Revoker um frühzeitiges Cleanup, geprüfte Stopzustände und kontrollierte Fristen erweitern oder einen kooperativen Entzug wählen; umfassend auf dem Zielsystem testen.

**Empfehlung des Gutachters:** A vor Abgabe, B als technische Folgearbeit bei ausreichender Zeit. Es wird kein produktionsreifer Debugger als Bacheloranforderung verlangt.

**Aufwand:** mittel: 30 Minuten bis 2 Stunden für A; sehr hoch für vollständige Härtung.

**Erwarteter Nutzen:** hoch.

**Relevanz für die Benotung:** hoch: betrifft die praktische Aussage „andere Zugriffe bleiben unbeeinflusst“.


**Kapitelübergreifende Befunde:** Die leserseitige Konsistenzgrenze F04 gilt auch für §5.4.5 und §5.9.2. F08 behandelt den finalen Build-/Teststand.

## 5. Fehlende Inhalte

Zusätzlich zu den Hauptbefunden: Die feste vmlinux.rs-Basis und ihre Herkunft sollten dem Zielkernel eindeutig zugeordnet werden. BTF zum Auflösen des LSM-Hooks ist nicht automatisch ein Nachweis portabler Relokation sämtlicher Rust-Feldzugriffe; helpers.rs liest feste generierte Felder. Die Arbeit begrenzt sich bereits auf einen Kernel, daher ist dies ein Reproduzierbarkeitshinweis, kein behaupteter Portabilitätsfehler.

## 6. Überflüssige oder redundante Inhalte

Mehrfach wiederholte Beschreibungen des Bankwechsels können auf einen zentralen Ablauf verweisen. Nicht jeder Rust-Grundbegriff muss ausführlich erklärt werden; ein vollständiges Policybeispiel wäre an dieser Stelle ergiebiger.

## 7. Quellen und Belege

Kernelhelper, Aya-Quellstand und proc_pid_status decken die UID-Aussage. Cargo-Build-Abhängigkeiten sind korrekt eingeordnet. Zu ergänzen sind die reale Tokio-Ausführung und Link-Lebensdauer. Die Behauptung einer „eingesetzten stabilen Cargo-Version“ in §5.1.2 passt nicht ohne Erläuterung zur in Kapitel 6 beschriebenen Nightly-Umgebung: als allgemein fehlende stabile Artefaktabhängigkeitsfunktion formulieren, nicht als tatsächlich verwendete Toolchain.

## 8. Bezug zum Quellcode

Der separate Code_Thesis_Audit.md enthält die Gegenüberstellung. Weitere begrenzte Punkte: command akzeptiert 16 Inhaltsbytes, während comm einen Nullabschluss benötigt; daraus können nicht passende Deny-Regeln entstehen. Die Map-ABI-Prüfung prüft Größen/Kapazität, aber keine semantische Schema-Version. Beides sollte als präzise Grenze benannt werden, nicht als pauschales Urteil über Rust-Sicherheit.

## 9. Beitrag zur Forschungsfrage

Das Kapitel belegt, dass die Architektur tatsächlich realisiert wurde. Die Frage nach technischen Einschränkungen verlangt hier nicht nur Beschreibung des Happy Paths, sondern insbesondere F05/F06/F14.

## 10. Wichtigste Maßnahmen

1. TODO-Abbildung ersetzen oder entfernen (F01).
2. Serielle/blockierende Laufzeitsteuerung richtig darstellen (F05).
3. Runtime-Ausfall und TCB ergänzen (F06).
4. ptrace-Risiken und Testgrenzen benennen (F14).
5. Policybeispiel und differenzierte Fail-closed-Tabelle ergänzen (F13).


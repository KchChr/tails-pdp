# Wissenschaftliche und konzeptionelle Probleme

## P0-01 – Namensgebende ASBAC-Primärliteratur und Related Work fehlen

**Fundstelle:** Kapitel 2, Abschnitt 2.3, PDF S. 7–8; `thesis/sections/02-grundlagen.tex`, Zeilen 51–65; Bibliografie.  
**Beschreibung:** ASBAC wird als eigene Erweiterung von ABAC beschrieben und nur über ein UseCON-Paper motiviert. Die direkt einschlägige ASBAC-Arbeit von Heutelbeck (SACMAT 2021, DOI `10.1145/3450569.3464397`) und die zugehörige SAPL-Architektur werden nicht zitiert oder abgegrenzt, obwohl `SAPL` als ungenutzter Webeintrag in der Bibliografie steht. Das etablierte ASBAC-Modell liefert fortlaufende Entscheidungen über Publish/Subscribe; der Prototyp pollt dagegen Zustände und offene FDs.

**Begründung:** Eine Bachelorarbeit muss ihren zentralen Begriff nach dem Stand der Forschung definieren und den eigenen Beitrag davon abgrenzen. Sonst bleibt unklar, ob die Arbeit ASBAC implementiert, eine Variante überträgt oder lediglich dynamisches ABAC/UCON-artige Nachkontrolle realisiert. Dies betrifft Forschungsstand, Begriffsvalidität und Eigenleistung.

**Lösungsmöglichkeiten:**

- **Lösung A (empfohlen):** ASBAC-Primärquelle aufnehmen, deren Architektur und Decision Streams korrekt darstellen und den Prototyp explizit als pollingbasierte Linux-Kernel-Variante bzw. Annäherung abgrenzen. *Vorteil:* wissenschaftlich sauber, stärkt Neuheitsbeitrag. *Nachteil:* mehrere Abschnitte müssen argumentativ angepasst werden. *Wirkung:* sehr hoch.
- **Lösung B:** Forschungsfrage und Titel auf „dynamische attributbasierte Zugriffskontrolle“ reduzieren. *Vorteil:* vermeidet falschen Modellanspruch. *Nachteil:* schwächt den namensgebenden Fokus und erfordert breite Umstellung. *Wirkung:* hoch.
- **Lösung C:** Behaupten, eine eigene ASBAC-Definition zu verwenden. *Vorteil:* geringer Umbau. *Nachteil:* wissenschaftlich schwach und terminologisch konfliktträchtig; nicht empfohlen.

**Priorität:** P0  
**Aufwand:** hoch (2–8 Stunden)  
**Erwarteter Nutzen:** sehr hoch; unmittelbarer Einfluss auf wissenschaftliche Validität und voraussichtlich auf die Note.

## P0-02 – „Unmittelbarer“ FD-Entzug ist durch Architektur und Code nicht erfüllt

**Fundstelle:** Kapitel 3, FA-07, PDF S. 14–15; `03-anforderungsanalyse.tex`, Zeilen 43–49. Kapitel 4.3.4/4.6.13–14, PDF S. 20/32–33. Kapitel 5.7, PDF S. 49–50. Code: `tails-pdp-userspace-pep/src/pep.rs`, Zeilen 105–131, 323–399; `fd_revoker.rs`, Zeilen 3–18, 38–86.

**Beschreibung:** Der Scan läuft einmal pro Sekunde. Zwischen `/proc`-Erfassung, Policyprüfung und `close(fd)` kann sich die FD-Belegung ändern. Nur ein Thread wird angehalten; andere Threads können dieselbe FD-Tabelle verändern. Duplikate, vererbte Deskriptoren, bereits erstellte `mmap`-Abbildungen und weitere Zugriffskanäle bleiben bestehen. PID 1 und der eigene Prozess werden ausdrücklich ausgenommen; `ptrace` kann zudem scheitern.

**Begründung:** Das Akzeptanzkriterium ist als harte Systemeigenschaft formuliert, tatsächlich liegt best-effort Enforcement mit messbarer Latenz und Abdeckungslücken vor. Ohne Präzisierung entsteht eine Diskrepanz zwischen Anforderung, Design, Implementierung und späterer Evaluation. Aus Security-Sicht ist insbesondere FD-Reuse ein TOCTTOU-Risiko: Im ungünstigen Fall wird nicht mehr der zuvor bewertete Zugriff geschlossen.

**Lösungsmöglichkeiten:**

- **Lösung A (empfohlen):** FA-07 auf „innerhalb eines periodischen Scanintervalls best-effort erkennen und einen zum Prüfzeitpunkt zugeordneten FD-Entzug versuchen“ präzisieren; Garantien und Nicht-Garantien explizit auflisten und messen. *Vorteil:* entspricht Code und Bachelor-Scope. *Nachteil:* schwächeres Sicherheitsversprechen. *Wirkung:* sehr hoch.
- **Lösung B:** Vor dem Entzug Identität erneut prüfen, Threadgruppe stabilisieren und Race-Tests ergänzen. *Vorteil:* reduziert Fehlentzug. *Nachteil:* hoher technischer Aufwand, keine vollständige Lösung. *Wirkung:* hoch.
- **Lösung C:** Ereignis-/kernelbasierte kontinuierliche Mediation zusätzlicher Operationen entwerfen. *Vorteil:* näher am Modell. *Nachteil:* sehr hoher Aufwand und vermutlich außerhalb des verbleibenden Bachelor-Scope. Als Ausblick geeignet.

**Priorität:** P0  
**Aufwand:** mittel für Claim-/Scope-Korrektur; sehr hoch für technische Härtung  
**Erwarteter Nutzen:** sehr hoch; verhindert einen zentralen Gutachtereinwand und beeinflusst die Note wahrscheinlich deutlich.

## Behoben – vormals P0-03: Subjekt-UID war nicht ausdrücklich definiert

**Fundstelle:** Kapitel 5.7.1/5.7.2, PDF S. 49; `tails-pdp-ebpf/src/hooks.rs`, Zeile 15; `file_open_static_policies.rs`, Zeile 73; `file_open_stream_policies.rs`, Zeile 133; `tails-pdp-userspace-pep/src/pep.rs`, Zeilen 381–399.

**Beschreibung:** Die ursprüngliche Bewertung unterstellte eine mögliche Abweichung zwischen `ctx.uid()` und dem ersten `Uid:`-Feld aus `/proc/<pid>/status`. Die Code- und API-Prüfung ergibt jedoch: Aya verwendet den BPF-Helper `bpf_get_current_uid_gid()`, der die Real UID liefert; das erste Feld in `/proc/<pid>/status` ist ebenfalls die Real UID. Das tatsächliche Problem war daher keine Implementierungsinkonsistenz, sondern die zuvor fehlende ausdrückliche Definition der Subjektidentität und ihres Geltungsbereichs.

**Begründung:** Zwei PEPs, die dieselbe Policy auswerten, müssen identische Subjektsemantik besitzen und diese nachvollziehbar dokumentieren. Real UID, Effective UID und Filesystem-UID haben unter Linux unterschiedliche Bedeutungen. Ohne Festlegung wäre unklar, welche Identität eine UID-gefilterte Policy tatsächlich kontrolliert.

**Lösungsmöglichkeiten:**

- **Umgesetzte Lösung A:** Real UID als verbindliche Subjektidentität festlegen und für beide Pfade belegen. Die Userspace-Auswahl wird durch einen Unit-Test mit abweichenden vier UID-Feldern abgesichert. Grenzen bei Credential-Wechseln, Threads und User Namespaces werden dokumentiert. Ein privilegierter Kernel-/Userspace-E2E-Test bleibt als Evaluationsszenario ausgewiesen und darf erst nach tatsächlicher Ausführung als Nachweis gelten. *Vorteil:* konsistente, überprüfbare Semantik ohne unnötigen Produktionscode-Umbau. *Nachteil:* andere Linux-Credentials sind bewusst nicht Teil des Modells. *Wirkung:* hoch.
- **Alternative B:** Mehrere Credential-Typen als explizite Policyattribute modellieren. *Vorteil:* feinere Sicherheitssemantik. *Nachteil:* deutlich größerer Entwurfs-, ABI- und Evaluationsaufwand. Für den gegenwärtigen Prototyp nicht empfohlen.

**Status:** in Code und Thesis umgesetzt; der privilegierte E2E-Nachweis ist Bestandteil der noch durchzuführenden Evaluation.
**Verbleibende Priorität:** P2 für die Ausführung und Dokumentation des E2E-Szenarios
**Aufwand:** mittel (30 Minuten bis 2 Stunden)
**Erwarteter Nutzen:** hoch; verhindert eine unklare Interpretation von UID-gefilterten Policies.

## P0-04 – Formale Platzhalter in der gerenderten Thesis

**Fundstelle:** Kapitel 1.4, PDF S. 5; `01-einleitung.tex`, Zeile 32 ff. Kapitel 5.1, PDF S. 38; `graphics/abhaengigkeiten.jpg` bzw. zugehörige Einbindung.

**Beschreibung:** „Aufbau der Arbeit“ ist leer. PDF-Seite 38 zeigt groß „TODO abhaengigkeiten Diagramm“ anstelle einer fertigen Abbildung.

**Begründung:** Beides ist in einer Abgabeversion unmittelbar sichtbar und signalisiert Unvollständigkeit unabhängig von der fachlichen Qualität.

**Lösungsmöglichkeiten:**

- **Lösung A (empfohlen):** Abschnitt 1.4 vervollständigen und Abbildung fachlich finalisieren; anschließend PDF vollständig rendern und prüfen. *Vorteil:* beseitigt Abgabe-Blocker. *Nachteil:* keiner außer Zeitaufwand.
- **Lösung B:** Abbildung entfernen und Abhängigkeiten als Tabelle/Text darstellen, falls die Grafik keinen Mehrwert bietet. *Vorteil:* schneller und häufig präziser. *Nachteil:* weniger visuelle Übersicht.

**Priorität:** P0  
**Aufwand:** mittel  
**Erwarteter Nutzen:** sehr hoch für formalen Eindruck; sicher benotungsrelevant, wenn ungeändert abgegeben.

## P1-01 – Reference-Monitor-Eigenschaften werden nicht am Gesamtsystem nachgewiesen

**Fundstelle:** Kapitel 2.1, PDF S. 6–7; Kapitel 4.6.1, PDF S. 23; Kapitel 5.9.3, PDF S. 52.

**Beschreibung:** Die drei klassischen Eigenschaften werden genannt, aber nicht komponentenweise geprüft. Die TCB umfasst mindestens Kernel, eBPF-Programme, Loader, Policy-/Attributquellen, gepinnte Maps, Userspace-PEP und dessen Privilegien. Vollständige Vermittlung ist wegen Hook-Scope und Nachkontrolllücken nicht gegeben; Tamper Resistance hängt von Root-/Capability- und bpffs-Berechtigungen ab; „small enough“ wird nicht operationalisiert.

**Begründung:** Eine bloße Analogie zu einem Reference Monitor darf nicht in eine Eigenschaftsbehauptung übergehen. Der Gutachter erwartet eine Matrix: Eigenschaft, zuständige Komponenten, erfüllte Teilaspekte, Gegenbeispiele, Restannahmen.

**Lösungsmöglichkeiten:**

- **Lösung A (empfohlen):** Eigene Untersektion mit TCB-/Trust-Boundary-Diagramm und Eigenschaftsmatrix; Ergebnis ausdrücklich „Reference-Monitor-orientiert“, nicht „Reference Monitor“. *Vorteil:* wissenschaftlich präzise. *Nachteil:* erfordert Security-Analyse. *Wirkung:* sehr hoch.
- **Lösung B:** Reference-Monitor-Anspruch auf den unmittelbaren `file_open`-PEP begrenzen. *Vorteil:* leichter belegbar. *Nachteil:* erklärt fortdauernde Nutzung nicht vollständig.

**Priorität:** P1  
**Aufwand:** hoch  
**Erwarteter Nutzen:** sehr hoch; wahrscheinlich deutlicher Noteneffekt.

## P1-02 – Kein explizites Threat Model und unzureichende Map-/Loader-Vertrauensanalyse

**Fundstelle:** Kapitel 4.2–4.6 und 5.9; gepinnte Maps unter `/sys/fs/bpf/tails-pdp`; Start via `sudo -E` in Kapitel 5.10.2.

**Beschreibung:** Es bleibt offen, gegen welchen Angreifer geschützt wird. Ein ausreichend privilegierter Prozess kann Programme, Links, Maps, Policydateien oder Attribute beeinflussen. Auch der hochprivilegierte Userspace-PEP ist selbst Teil der Angriffsfläche. Die tatsächlichen Dateirechte, Capabilities, Ownership und Lebenszyklen werden nicht als Sicherheitsannahmen festgelegt.

**Begründung:** Ohne Angreifermodell sind Aussagen wie fail-closed, manipulationssicher oder systemweite MAC-Policy nicht bewertbar.

**Lösungsmöglichkeiten:**

- **Lösung A (empfohlen):** Angreiferfähigkeiten, Schutzziele, TCB, Trust Boundaries und explizite Nicht-Ziele tabellarisch definieren. Rechte an Quellen, bpffs, Loader und BPF-Link dokumentieren. *Vorteil:* macht Claims prüfbar. *Nachteil:* zeigt bewusst Grenzen. *Wirkung:* hoch.
- **Lösung B:** Security-Anspruch klar auf funktionalen Prototyp ohne Schutz vor privilegierten Angreifern begrenzen. *Vorteil:* geringer Aufwand. *Nachteil:* weniger starke Aussage.

**Priorität:** P1  
**Aufwand:** hoch  
**Erwarteter Nutzen:** hoch; direkte Relevanz für wissenschaftliche Einordnung und Note.

## P1-03 – „Fail-closed“ gilt nur für einen Teil des Systems

**Fundstelle:** Kapitel 5.9.3, PDF S. 52; `pep.rs`, Zeilen 113–130, 299–319; Stream-Bedingungen bei fehlenden Attributen (`pep.rs` 265–270; eBPF Stream-Policy 116–120).

**Beschreibung:** Der Kernel-Tail-Call-Pfad verweigert bei technischen Fehlern. Dagegen führt ein Fehler beim Userspace-Scan oder `ptrace`-Entzug dazu, dass der bestehende Zugriff fortdauert. Ein fehlendes Attribut lässt eine bedingte Deny-Policy nicht matchen, wodurch der Zugriff bei deny-only/default-permit erlaubt bleibt. Die Thesis trennt technische und fachliche Semantik teilweise, aber die Überschrift „Fail-closed“ kann als Systemeigenschaft missverstanden werden.

**Begründung:** Fail-open/fail-closed muss pro Fehlerklasse und Komponente angegeben werden. „Missing attribute“ ist eine Policy-Semantikentscheidung und muss begründet werden.

**Lösungsmöglichkeiten:**

- **Lösung A (empfohlen):** Fehlerfallmatrix erstellen: Kernel-Mapfehler, fehlendes Attribut, Loader-Ausfall, PEP-Ausfall, Scanfehler, Revocation-Fehler, Policy-Parsefehler. Jeweils beobachtbares Verhalten und Sicherheitswirkung angeben. *Vorteil:* präzise und testbar. *Nachteil:* zusätzlicher Evaluationsaufwand.
- **Lösung B:** Begriff nur für die eBPF-Tail-Call-Kette verwenden und alle anderen Fälle separat benennen. *Vorteil:* schnell. *Nachteil:* ersetzt keine Tests.

**Priorität:** P1  
**Aufwand:** mittel  
**Erwarteter Nutzen:** hoch; verhindert überzogene Security-Claims.

## P1-04 – Forschungsbeitrag und Methode sind nicht explizit

**Fundstelle:** Kapitel 1 insgesamt; Kapitel 3–6.

**Beschreibung:** Die Arbeit enthält Forschungsfrage, Anforderungen, Entwurf und Implementierung, benennt aber weder die Forschungslücke gegenüber Related Work noch eine Methode (z. B. artefaktorientierter Design-/Build-and-Evaluate-Ansatz) und keine explizite Beitragsliste.

**Begründung:** Eine Implementierung wird erst durch nachvollziehbare Methode, begründete Entscheidungen und Evaluation zu einer wissenschaftlichen Arbeit. Ohne Beitragsabgrenzung droht Kapitel 5 als Projektdokumentation statt Erkenntnisbeitrag zu wirken.

**Lösungsmöglichkeiten:**

- **Lösung A (empfohlen):** In Kapitel 1 Forschungslücke, Scope, Methode und 3–4 konkrete Beiträge ergänzen; Kapitel 6 direkt auf Forschungsfrage und Anforderungen zurückführen. *Vorteil:* stärkt roten Faden erheblich. *Nachteil:* moderate Überarbeitung.
- **Lösung B:** Eigenes Methodik-Kapitel. *Vorteil:* sehr sichtbar. *Nachteil:* für Bachelorarbeit möglicherweise unnötig umfangreich; kurze Einleitungssektion genügt oft.

**Priorität:** P1  
**Aufwand:** mittel bis hoch  
**Erwarteter Nutzen:** sehr hoch; wahrscheinlicher Noteneffekt.

## P1-05 – Dateiidentität und Policy-Lebenszyklus besitzen eine Schutzlücke

**Fundstelle:** Kapitel 4.6.12, PDF S. 31; Kapitel 5.4/5.10.3; `tails-pdp-common/src/lib.rs` (Pfadauflösung), Policy-Watcher.

**Beschreibung:** Eine Policy wird beim Laden an Device/Inode gebunden. Wird die Ressource atomar ersetzt, erhält sie typischerweise eine neue Inode; ohne Änderung im Policy-Verzeichnis wird die Policy nicht zwingend neu übersetzt. Der Text sagt lediglich, die Policy „muss entsprechend neu verarbeitet werden“, beschreibt aber keinen automatischen Trigger oder das Verhalten in der Schutzlücke.

**Begründung:** Für pfadbasiert formulierte Policies ist unklar, ob die Semantik den Pfad oder das konkrete Dateiobjekt schützen soll. Diese Entscheidung beeinflusst Umgehbarkeit und Bedienbarkeit.

**Lösungsmöglichkeiten:**

- **Lösung A (empfohlen):** Objekt- vs. Pfadsemantik ausdrücklich festlegen, Replacement-Test durchführen und die nötige manuelle Policy-Aktualisierung als Limitierung dokumentieren. *Vorteil:* geringer Implementierungsaufwand, klare Semantik.
- **Lösung B:** Ressourcenpfade beobachten und betroffene Policies automatisch neu auflösen. *Vorteil:* schließt praktische Lücke. *Nachteil:* zusätzliche Races und hoher Aufwand.

**Priorität:** P1  
**Aufwand:** mittel für Dokumentation/Test, hoch für Implementierung  
**Erwarteter Nutzen:** hoch; relevante Security- und Nachvollziehbarkeitswirkung.

## P2-01 – eBPF-LSM-Auswahl ist nicht systematisch verglichen

**Fundstelle:** Kapitel 4.6.2–4.6.3, PDF S. 23–25.

**Beschreibung:** „Änderungen schneller testen“ und Verifier-Prüfung sind plausible Vorteile, aber kein vollständiger wissenschaftlicher Technologievergleich. Kriterien wie Hook-Abdeckung, Deployment, Portabilität, Verifier-/Helper-Grenzen, TCB, Performance und Wartbarkeit fehlen in einer vergleichbaren Matrix.

**Begründung:** Die Wahl trägt die gesamte Architektur und sollte anhand der Anforderungen bewertet werden.

**Lösungen:** **A (empfohlen):** kompakte Alternativenmatrix (klassisches LSM, eBPF-LSM, fanotify, rein userspacebasiert) mit klaren Kriterien. **B:** Anspruch als bewusst pragmatische Prototypentscheidung deklarieren. A ist aussagekräftiger, B schneller.

**Priorität:** P2  
**Aufwand:** mittel  
**Erwarteter Nutzen:** mittel bis hoch; stärkt Argumentation, moderater Noteneffekt.

## P2-02 – Kapitel 4 und 5 sind teilweise redundant

**Fundstelle:** Kapitel 4.2–4.6 und Kapitel 5.2–5.9.

**Beschreibung:** Datenflüsse, Maps, Generationen, Tail Calls und PEP-Rollen werden mehrfach ähnlich erklärt. Konzept, Entscheidung und konkrete Implementierung sind nicht immer sauber getrennt.

**Begründung:** Redundanz erhöht Umfang, erschwert roten Faden und erzeugt Inkonsistenzrisiken.

**Lösungen:** **A (empfohlen):** Kapitel 4 auf Anforderungen, Alternativen, Entscheidungen und Konsequenzen begrenzen; Kapitel 5 auf konkrete Umsetzung und Codebezug. **B:** Wiederholungen durch gezielte Rückverweise verkürzen.

**Priorität:** P2  
**Aufwand:** hoch  
**Erwarteter Nutzen:** mittel; verbessert Lesbarkeit deutlich, Note eher indirekt.

## P2-03 – Sprache und Terminologie sind stellenweise unpräzise

**Fundstelle:** u. a. Kapitel 1.1 („LSM … mittels ABAC“), Kapitel 4.1 („praktische“ kleingeschrieben), FA-07 („unmittelbar“), wechselnd „Streamingattribute“, „Stream-Attribute“, „Streampolicies“, „Kernelprogramm“.

**Beschreibung:** Mehrere Begriffe werden ohne feste Definition oder zu weitgehend verwendet. Einige Sätze machen aus plausiblen Entwurfsentscheidungen Notwendigkeiten („muss“, „verhindert“), obwohl nur ein Prototypweg gezeigt wird.

**Begründung:** Wissenschaftliche Sprache verlangt prüfbare Reichweitenangaben und konsistente Terminologie.

**Lösungen:** **A (empfohlen):** Terminologieliste und gezielte Claim-Prüfung („belegt“, „Code zeigt“, „Evaluation muss zeigen“, „Annahme“). **B:** abschließendes reines Lektorat; behebt jedoch keine Argumentationsprobleme.

**Priorität:** P2  
**Aufwand:** hoch  
**Erwarteter Nutzen:** mittel; merklicher Qualitätsgewinn.

## P3-01 – Formale PDF-Gestaltung

**Fundstelle:** gesamte PDF, besonders Inhaltsverzeichnis und Literatur S. 57–58.

**Beschreibung:** Hyperlinks besitzen sichtbare farbige Rahmen; Titelseite enthält nur Minimalangaben; Literatur-URLs dominieren optisch. Ob Sperrvermerk, Erklärung, Abstract, Hochschul-/Studiengangsangaben erforderlich sind, hängt von der Prüfungsordnung ab.

**Begründung:** Kein wissenschaftlicher Kernmangel, aber eine professionelle Abgabe sollte formale Vorgaben vollständig erfüllen.

**Lösungen:** **A (empfohlen):** Hochschulvorlage/Prüfungsordnung prüfen, Linkdarstellung drucktauglich konfigurieren, Literaturstil vereinheitlichen. **B:** aktuelle Darstellung belassen, falls Vorgaben dies erlauben.

**Priorität:** P3 (Pflichtbestandteile ggf. P0)  
**Aufwand:** gering bis mittel  
**Erwarteter Nutzen:** gering bis mittel; primär formaler Eindruck.

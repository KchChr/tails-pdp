# Abgleich der Thesis mit dem FTK-Regelwerk

Stand: 19.09.2026. Grundlage: [FTK-Regelwerk](/Users/ck/Code/tails-pdp/thesis/ftk-regelwerk.md), abgeleitet aus dem FTK-Leitfaden vom 15.04.2024.

Erneut geprüft wurden die sieben eingebundenen Kapitel, die LaTeX-Hauptdatei, die Literaturangaben und Querverweise sowie die vorhandene **85-seitige PDF**. Die bestehende Erklärung wurde auf ihre Einbindung geprüft. Die PDF wurde nicht neu gebaut; die eingebundenen Kapitel und die Hauptdatei sind nicht neuer als die PDF. PDF-Seitenangaben zählen ab dem Titelblatt; gedruckte Seitenzahlen werden zusätzlich angegeben. Die Satzkontrolle erfolgte gezielt, insbesondere an Verzeichnissen, Abbildungen und Tabellen. Eine vollständige visuelle Kontrolle jeder Seite, erneute fachliche Prüfung aller externen Quellen, ein Code-Audit und Wiederholungen der Linux-Tests waren nicht Bestandteil dieses Abgleichs.

Die Thesis wurde nicht verändert. Zeilennummern beziehen sich auf den geprüften Quellstand.

## Einordnung

Die sieben Hauptkapitel entsprechen grundsätzlich der empfohlenen Argumentationsfolge. Anforderungen besitzen überwiegend Akzeptanzkriterien, die Evaluation greift sie wieder auf, und der Schluss grenzt die Ergebnisse ausdrücklich ein. Nach Berücksichtigung der Rückmeldung zu F01 und der angepassten Draft-Konfiguration zu F03 verbleiben **sechs aktuell bearbeitbare Punkte** (F04, F06, F07, F08, F11, F13). Fünf Befunde sind erledigt; F01 wartet auf das Prüfungsamt, F03 ist für den PDF-Export umgesetzt und verbleibt nur als finale Abgabeprüfung. **Empfehlungen des Leitfadens werden dabei nicht als zwingende Vorschriften behandelt.**

Prioritäten: **hoch** = vor der Abgabe bzw. Ergebnisfreigabe klären; **mittel** = inhaltlich oder strukturell überarbeiten; **niedrig** = formale Angleichung nach Festlegung der Formatvorlage. Die Priorität beschreibt den Überarbeitungsbedarf, nicht den Verbindlichkeitsgrad der Regel.

## 1. Zurückgestellte Abgabeaufgaben

### F01 – Erklärung wird vom Prüfungsamt bereitgestellt

**Status: wartet auf Zusendung durch das Prüfungsamt; derzeit kein Handlungsbedarf.**

- **Regel:** A01, Vorgabe für die Abgabe; Leitfaden S. 10.
- **Fundstelle:** [thesis.tex:95](/Users/ck/Code/tails-pdp/thesis/thesis.tex:95), [08-selbststaendigkeitserklaerung.tex](/Users/ck/Code/tails-pdp/thesis/sections/08-selbststaendigkeitserklaerung.tex).
- **Einordnung:** Laut Rückmeldung des Nutzers wird die maßgebliche Erklärung vom Prüfungsamt übersandt und kann derzeit noch nicht ausgefüllt werden. Die vorbereitete LaTeX-Datei ist auskommentiert. Das wird im jetzigen Arbeitsstand nicht als zu behebender Textmangel gewertet.
- **Späterer Schritt:** Nach Erhalt die Erklärung des Prüfungsamts ausfüllen, individuell unterschreiben und entsprechend dessen Vorgaben zur Abgabe beifügen. Die vorbereitete eigene Fassung muss dafür nicht vorab eingebunden werden.

### F03 – PDF-Benennung im Draft-Export umgesetzt

**Status: für den PDF-Export umgesetzt; finale Abgabebenennung später prüfen.**

- **Regel:** A05, Vorgabe für die finale Übergabe; Leitfaden S. 12–13.
- **Fundstelle:** [draft.run.xml:3](/Users/ck/Code/tails-pdp/.run/draft.run.xml:3).
- **Befund:** Die Run-Konfiguration kopiert die kompilierte PDF nach `drafts/YYYYMMDD_HHMMSS_Christian_Koch_9227725_ASBAC_im_Linuxkernel_draft.pdf`. Der Export enthält damit den Namen und eine Kurzform des Arbeitstitels. Ein entsprechend benannter Draft liegt bereits vor.
- **Einordnung:** Der frühere pauschale Hinweis auf die fehlende identifizierbare PDF-Benennung ist damit überholt. Die internen Arbeitsnamen `thesis.tex` und `thesis.pdf` sind kein aktueller Regelkonflikt.
- **Späterer Schritt:** Bei der finalen Übergabe den endgültigen PDF-Dateinamen mit dem Arbeitstitel abgleichen und auch die übergebene TeX-Hauptdatei mit dem Namen versehen. Die Draft-Konfiguration benennt diese Quelldatei nicht um. Hierfür ist jetzt keine Änderung der Arbeitsdateien erforderlich.

## 2. Inhaltliche und strukturelle Konflikte

### F04 – OA-03 bewertet eine Messung als Erfüllung einer nicht operationalisierten Qualitätsforderung

- **Priorität:** mittel.
- **Regel:** W06, Empfehlung; W10 und W11, abgeleitete Prüfregeln; Leitfaden S. 3–4 und 8.
- **Fundstellen:** [03-anforderungsanalyse.tex:92](/Users/ck/Code/tails-pdp/thesis/sections/03-anforderungsanalyse.tex:92), [06-evaluation.tex:530](/Users/ck/Code/tails-pdp/thesis/sections/06-evaluation.tex:530), [06-evaluation.tex:561](/Users/ck/Code/tails-pdp/thesis/sections/06-evaluation.tex:561).
- **Befund:** OA-03 fordert, kontrollierte Zugriffe nicht „unverhältnismäßig“ zu verlangsamen. Das Akzeptanzkriterium verlangt inzwischen, die Auswirkungen auf die Ausführungszeit zu betrachten **und zu bewerten**. Ein Maßstab für „unverhältnismäßig“ wird dabei weiterhin nicht festgelegt. Die Evaluation erklärt zutreffend, dass keine Latenzgrenze festgelegt wurde, bewertet OA-03 aber als erfüllt, weil Aufwand und Latenzen gemessen wurden.
- **Konflikt:** Die quantitative Untersuchung ist belegt; die geforderte Bewertung der Verhältnismäßigkeit ist damit jedoch nicht entschieden. Die Erfolgsaussage ist stärker als der definierte Nachweis.
- **Korrektur:** Entweder OA-03 ausdrücklich als Anforderung zur Performance-Charakterisierung formulieren oder die Bewertung trennen: „quantitativ untersucht; Angemessenheit mangels vorab begründetem Maßstab nicht bewertet“. Keinen nachträglich an die Messwerte angepassten Grenzwert als ursprüngliches Kriterium ausgeben.

### F06 – Kapitel 4 enthält konkrete Implementierungsdetails, die Kapitel 5 bereits behandelt

- **Priorität:** mittel.
- **Regel:** W05 und W08, Empfehlungen; Leitfaden S. 3–4.
- **Fundstellen:** [04-konzeption.tex:100](/Users/ck/Code/tails-pdp/thesis/sections/04-konzeption.tex:100), [04-konzeption.tex:370](/Users/ck/Code/tails-pdp/thesis/sections/04-konzeption.tex:370), [04-konzeption.tex:560](/Users/ck/Code/tails-pdp/thesis/sections/04-konzeption.tex:560), [04-konzeption.tex:619](/Users/ck/Code/tails-pdp/thesis/sections/04-konzeption.tex:619).
- **Befund:** Die Konzeption benennt die Rust-Funktion `PolicyTime::from_unix_seconds`, das Ein-Sekunden-Intervall, `inotify` und die konkrete 100-ms-Verzögerung, einzelne Map-Namen, Kernelstrukturfelder `i_ino`/`s_dev` sowie den `ptrace`-basierten `close`-Aufruf auf x86_64. Kapitel 5 beschreibt dieselben technischen Mechanismen erneut, etwa [05-entwurf-und-umsetzung.tex:267](/Users/ck/Code/tails-pdp/thesis/sections/05-entwurf-und-umsetzung.tex:267) und [05-entwurf-und-umsetzung.tex:343](/Users/ck/Code/tails-pdp/thesis/sections/05-entwurf-und-umsetzung.tex:343).
- **Konflikt:** Die empfohlene Trennung zwischen konzeptioneller Modellbildung und technischer Umsetzung wird dadurch unscharf.
- **Korrektur:** In Kapitel 4 Zuständigkeiten, Datenflüsse, Konsistenzmodell, fachliche Entscheidungen und begründete Alternativen behalten. Funktions-/Feldnamen, feste Intervalle und konkrete Systemaufrufmechanik in Kapitel 5 bündeln. Da eBPF-LSM Teil der Forschungsfrage ist, muss die Konzeption nicht künstlich jeden Technologiebezug verlieren.

### F07 – Forschungsstand enthält Grundlagen und Abgrenzungen, aber wenig vergleichende Einordnung vorhandener Lösungen

- **Priorität:** mittel.
- **Regel:** W03, Empfehlung; Leitfaden S. 3–4.
- **Fundstellen:** [02-grundlagen.tex:51](/Users/ck/Code/tails-pdp/thesis/sections/02-grundlagen.tex:51), [02-grundlagen.tex:121](/Users/ck/Code/tails-pdp/thesis/sections/02-grundlagen.tex:121), [02-grundlagen.tex:200](/Users/ck/Code/tails-pdp/thesis/sections/02-grundlagen.tex:200), [04-konzeption.tex:259](/Users/ck/Code/tails-pdp/thesis/sections/04-konzeption.tex:259).
- **Befund:** ASBAC/SAPL, Usage Control und XACML werden eingeordnet. SELinux, Smack, AppArmor und TOMOYO erscheinen vor allem als Beispiele; Aya, libbpf und BCC als Werkzeuge. Ein zusammenhängender Vergleich vorhandener Lösungen hinsichtlich dynamischer Attribute, fortdauernder Autorisierung und Linux-Durchsetzung fehlt. Teile der Abgrenzung zu klassischen LSM stehen erst bei den Entwurfsentscheidungen.
- **Konflikt:** Die Grundlagen sind vorhanden, die im Leitfaden empfohlene Perspektive auf bestehende Arbeiten und konkurrierende Lösungsansätze ist jedoch nur teilweise ausgearbeitet. Die Überschrift „Grundlagen“ ist für sich genommen kein Verstoß.
- **Korrektur:** Kapitel 2 um eine gezielte vergleichende Einordnung ergänzen und daraus die verbleibende Herausforderung der Arbeit ableiten. Ein literaturgestützter Vergleich genügt hierfür; daraus folgt keine pauschale Pflicht zu neuen Vergleichsbenchmarks.

### F08 – Für EA-01 und EA-03 bleibt die abschließende Bewertung uneindeutig

- **Priorität:** mittel.
- **Regel:** W06, Empfehlung; W10, abgeleitete Prüfregel; Leitfaden S. 3–4.
- **Fundstellen:** [03-anforderungsanalyse.tex:108](/Users/ck/Code/tails-pdp/thesis/sections/03-anforderungsanalyse.tex:108), [06-evaluation.tex:175](/Users/ck/Code/tails-pdp/thesis/sections/06-evaluation.tex:175), [06-evaluation.tex:566](/Users/ck/Code/tails-pdp/thesis/sections/06-evaluation.tex:566).
- **Befund:** Für EA-01 bis EA-03 fehlen explizite Akzeptanzkriterien. Die Evaluation führt zwar die Kategorien „erfüllt“, „teilweise erfüllt“ und „nicht erfüllt“ ein, erklärt bei EA-01 und EA-03 aber nur, die Architektur „unterstützt“ diese Anforderungen. EA-02 erhält dagegen ausdrücklich die Bewertung „teilweise erfüllt“.
- **Konflikt:** Die Rückbindung an die Anforderungen ist vorhanden, liefert für EA-01 und EA-03 jedoch keinen eindeutig abgeschlossenen Bewertungsstatus und keinen gleich klaren Bewertungsmaßstab.
- **Korrektur:** Geeignete qualitative Kriterien nennen und je Anforderung eine begründete Bewertung mit Verweis auf konkrete Architektur- oder Implementierungsstellen abgeben. Zusätzliche Laufzeittests sind dafür nicht automatisch erforderlich.

## 3. Abweichungen von den Layout- und Darstellungsorientierungen

Die folgenden Befunde sind anhand des Quellstands bzw. der vorhandenen PDF belegbar. Ihre Verbindlichkeit hängt von der vereinbarten Formatvorlage ab, da § 2.2 des Leitfadens ausdrücklich „Orientierungen“ beschreibt.

### F11 – Zwei Darstellungsobjekte besitzen keinen ausdrücklichen Textverweis

- **Priorität:** niedrig.
- **Regel:** Regelwerk § 3, Bezugnahme auf Abbildungen und Tabellen; Leitfaden S. 7.
- **Fundstellen:** [04-konzeption.tex:68](/Users/ck/Code/tails-pdp/thesis/sections/04-konzeption.tex:68), [06-evaluation.tex:438](/Users/ck/Code/tails-pdp/thesis/sections/06-evaluation.tex:438).
- **Befund:** Die Labels `fig:konzeption-architektur` und `tab:funktionale-ergebnisse` sind definiert, werden aber im eingebundenen Text nicht referenziert. Die umliegenden Absätze behandeln den jeweiligen Inhalt, nennen jedoch die Abbildung bzw. Ergebnistabelle nicht ausdrücklich.
- **Konflikt:** Die geforderte Platzierung nach der ersten Bezugnahme ist damit nicht eindeutig nachvollziehbar.
- **Korrektur:** Unmittelbar vorher je einen inhaltlich passenden Satz mit Abbildungs-/Tabellenverweis ergänzen. Die Orientierung zur Fettschrift bei der ersten Erwähnung wird auch bei vorhandenen Verweisen, beispielsweise [05-entwurf-und-umsetzung.tex:18](/Users/ck/Code/tails-pdp/thesis/sections/05-entwurf-und-umsetzung.tex:18), noch nicht umgesetzt; gegebenenfalls einheitlich behandeln.

### F13 – Abbildung und Tabelle erscheinen erst nach Beginn des nächsten Abschnitts

**Status: neu festgestellt; offen.**

- **Priorität:** niedrig.
- **Regel:** Regelwerk § 3, Platzierung von Abbildungen und Tabellen; Layoutempfehlung, Leitfaden S. 7.
- **Fundstellen:** [04-konzeption.tex:68](/Users/ck/Code/tails-pdp/thesis/sections/04-konzeption.tex:68) mit folgendem Abschnitt bei [Zeile 76](/Users/ck/Code/tails-pdp/thesis/sections/04-konzeption.tex:76); [05-entwurf-und-umsetzung.tex:18](/Users/ck/Code/tails-pdp/thesis/sections/05-entwurf-und-umsetzung.tex:18) mit folgendem Abschnitt bei [Zeile 55](/Users/ck/Code/tails-pdp/thesis/sections/05-entwurf-und-umsetzung.tex:55).
- **Befund:** Abbildung 1 gehört zu Abschnitt 4.2 „Architektur“, erscheint aber erst auf PDF-Seite 23 (gedruckt 19), nachdem Abschnitt 4.3 „Datenfluss“ bereits auf PDF-Seite 22 (gedruckt 18) begonnen hat. Tabelle 1 wird in Abschnitt 5.1.1 eingeführt, erscheint jedoch erst auf PDF-Seite 42 (gedruckt 38); Abschnitt 5.1.2 beginnt bereits auf PDF-Seite 41 (gedruckt 37).
- **Konflikt:** Die Layoutorientierung sieht die Ausgabe vor Beginn des nächsten Abschnitts vor. Die Reihenfolge im LaTeX-Quelltext allein stellt dies bei gleitenden Objekten nicht sicher. Dieser Befund ist unabhängig von den inzwischen korrigierten Tabellenüberschriften (F10).
- **Korrektur:** An diesen Abschnittsgrenzen die Ausgabe der ausstehenden Gleitobjekte sicherstellen, beispielsweise durch gezielte Float-Barrieren, und anschließend die PDF kontrollieren. Den fehlenden Textverweis auf Abbildung 1 zusätzlich gemäß F11 ergänzen.

## 4. Erledigte Befunde

Die folgenden Korrekturen sind im aktuellen Stand vorhanden. Die früheren Fehlerbeschreibungen wurden entfernt, damit sie nicht als noch offene Aufgaben gelesen werden.

| ID | Aktueller Stand und Nachweis |
| --- | --- |
| F02 – Zitationskürzel | Q05 ist laut Nutzer anzuwenden. [thesis.tex:18](/Users/ck/Code/tails-pdp/thesis/thesis.tex:18) verwendet `biblatex`, `style=alphabetic` und Biber. Die 38 Literaturkennungen erhalten eindeutige Kürzel. Die konfigurierte Kürzelbildung lässt führende Artikel bei den erfassten Körperschaftsautoren weg. |
| F05 – Generationskonsistenz | Die freigegebenen Korrekturen in [Kapitel 4](/Users/ck/Code/tails-pdp/thesis/sections/04-konzeption.tex:398) und [Kapitel 5](/Users/ck/Code/tails-pdp/thesis/sections/05-entwurf-und-umsetzung.tex:202) unterscheiden vollständige Vorbereitung vor der Aktivierung von einer nicht garantierten unveränderten Lesesicht bei erneuter Bankverwendung. Der frühere Widerspruch ist behoben; dies ist kein neuer Laufzeitnachweis. |
| F09 – Seitennummerierung | [thesis.tex:71](/Users/ck/Code/tails-pdp/thesis/thesis.tex:71) bis Zeile 83 setzt Titel ohne Seitenzahl, Inhaltsverzeichnis römisch und Haupttext arabisch ab 1. Die aktuelle PDF entspricht dieser Abfolge. |
| F10 – Tabellenüberschriften | Die drei Tabellenbeschriftungen in Kapitel 5 stehen nun oberhalb der Tabellenkörper: [Zeile 21](/Users/ck/Code/tails-pdp/thesis/sections/05-entwurf-und-umsetzung.tex:21), [Zeile 129](/Users/ck/Code/tails-pdp/thesis/sections/05-entwurf-und-umsetzung.tex:129), [Zeile 228](/Users/ck/Code/tails-pdp/thesis/sections/05-entwurf-und-umsetzung.tex:228). |
| F12 – Zentrale Formatierung | Überschriftengrößen, abgesetzte kursive vierte Ebene, Absatzabstände, Tabellen-/Beschriftungsgröße und rechter Seitenfuß mit Trennlinie sind in [thesis.tex](/Users/ck/Code/tails-pdp/thesis/thesis.tex) konfiguriert. Die beauftragte Korrektur ist umgesetzt. Die genaue Schriftfamilie bleibt ein gesonderter Abstimmungspunkt, siehe unten. |

## 5. Offene Nachweise – keine belegten Verstöße

| Bereich | Beobachtung und Grenze der Prüfung | Nächster sinnvoller Schritt |
| --- | --- | --- |
| Installations- und Programmierhandbuch (S02/S03, A03) | [Kapitel 5.10](/Users/ck/Code/tails-pdp/thesis/sections/05-entwurf-und-umsetzung.tex:389) beschreibt Build und Start; die [README](/Users/ck/Code/tails-pdp/README.md:3) enthält Voraussetzungen und Bedienhinweise. Ein gesondertes finales Handbuchpaket ist damit noch nicht belegt. Die README nennt unversioniertes Nightly, während die Evaluation einen datierten Stand dokumentiert. Daraus folgt nicht, dass extern keine Handbücher existieren. | Aus vorhandener Dokumentation eine eindeutige Anleitung für das tatsächlich evaluierte Zielsystem zusammenstellen, einschließlich Kernel-/BTF-/BPF-LSM-Voraussetzungen und Berechtigungen. Schnittstellendokumentation als Programmierhandbuch identifizierbar machen. Die Grenze von drei Arbeitsschritten erst am finalen Ablauf bewerten. |
| Abbildungsherkunft (Q09–Q11) | Die Crate-Grafik ist als eigene Darstellung bezeichnet; zur Architekturgrafik liegt eine bearbeitbare `.drawio`-Datei vor. Daraus lässt sich keine fremde Urheberschaft und folglich auch keine fehlende Rechteklärung ableiten. | Herkunft prüfen, falls Fremdmaterial übernommen wurde; nur dann die vorgeschriebene Dokumentation der Nutzungsrechte verlangen. |
| Literaturformat (Q08) | Der aktuelle Stil ist `biblatex/alphabetic`; der frühere Hinweis auf `plainnat` ist überholt. Die genaue Namensformatierung ist wegen widersprüchlicher Leitfadenbeispiele weiterhin ein Abstimmungspunkt. | Gewählten Literaturstil mit der vereinbarten Vorlage abgleichen; die Kürzelvorgabe aus F02 ist bereits umgesetzt. |
| Schrift und Diagrammgestaltung | `newtxtext` ist eine Times-orientierte LaTeX-Schrift, nicht wörtlich Times New Roman. Zentrale LaTeX-Einstellungen bestimmen außerdem nicht die Schrift innerhalb eingebundener Rastergrafiken. | Zulässigkeit der Schrift und Gestaltung der Diagramme anhand der vereinbarten Formatvorlage klären; daraus hier keinen zusätzlichen sicheren Verstoß ableiten. |
| Abbildungs-/Tabellen-/Abkürzungsverzeichnisse | [thesis.tex:80](/Users/ck/Code/tails-pdp/thesis/thesis.tex:80) erzeugt nur das Inhaltsverzeichnis. Der Leitfaden beschreibt weitere Verzeichnisse, legt aber nicht eindeutig fest, dass jede Arbeit alle davon enthalten muss. | Erforderliche Verzeichnisse mit der Formatvorlage klären; nicht allein aus ihrer Erwähnung eine allgemeine Pflicht ableiten. |
| Planung und Betreuung (P01–P09) | Exposéfreigabe, Anmeldung, verbindlicher Titel, Betreuungstermine und Vereinbarungen sind aus den sieben Kapiteln nicht verifizierbar. | Anhand der tatsächlichen Studien- und Betreuungsunterlagen prüfen. |
| Finale Übergabe (S07–S10, A02–A07) | Cloud-Ablage, Lizenzabsprachen, vollständige Binär-/Abhängigkeitspakete, unterschriebene Dokumente, Submission-Tag und Kolloquium wurden nicht als externe Zustände geprüft. | Vor Abgabe den konkreten Übergabeumfang und die aktuell geltenden Prüfungsamtsvorgaben kontrollieren. |

## 6. Geprüfte Punkte ohne festgestellten Regelkonflikt

- Die sieben Hauptkapitel folgen der empfohlenen Grundstruktur; eine Umbenennung von „Grundlagen“ in „State of the Art“ ist nicht an sich erforderlich.
- Forschungsfrage, Zielsetzung und Prototypgrenzen sind in der Einleitung vorhanden. Der Schluss beantwortet die Frage und behandelt Grenzen sowie weitere Arbeiten.
- Funktionale, operative und entwicklungsbezogene Anforderungen sind in Kapitel 3 gebündelt. Kapitel 6 enthält eine eigene Anforderungsbewertung; F04 und F08 betreffen konkrete Einschränkungen dieser Bewertung.
- Alle **38 verschiedenen zitierten Literaturkennungen** sind in `literatur.bib` vorhanden und erscheinen im bestehenden Literaturverzeichnis. Kein fehlender Bibliographieeintrag wurde festgestellt. Das ist keine Bestätigung der inhaltlichen Tragfähigkeit jeder Quelle.
- Alle verwendeten LaTeX-Verweise besitzen ein definiertes Ziel. F11 betrifft den umgekehrten Fall: vorhandene Darstellungen ohne ausdrücklichen Verweis.
- Der Text zeigt kurze Policy-/Attributbeispiele, keine langen vollständigen Programmabdrucke. Kein belegter Konflikt mit W09.
- Hauptkapitel werden durch Seitenumbrüche getrennt. Die Seitenränder entsprechen den genannten Werten.
- Die Evaluation benennt Aussagegrenzen, die geringe Zahl bestimmter Wiederholungen, verbleibende Race-Risiken und die begrenzte Übertragbarkeit. Der Schluss behauptet weder allgemeine Race-Freiheit noch Echtzeit- oder Produktionstauglichkeit.

## 7. Noch zu lösende Probleme

| Reihenfolge | ID | Aufgabe | Einordnung |
| --- | --- | --- | --- |
| 1 | F04 | OA-03 und die Erfolgsaussage in der Evaluation auf denselben Bewertungsmaßstab bringen. | Inhaltlich offen |
| 2 | F08 | EA-01 und EA-03 mit qualitativen Kriterien und eindeutigen Bewertungsstatus abschließen. | Inhaltlich offen |
| 3 | F07 | Vorhandene Lösungen im Forschungsstand gezielt vergleichen und die eigene Arbeit daraus abgrenzen. | Empfohlene inhaltliche Ergänzung |
| 4 | F06 | Konzeption und Umsetzung von wiederholten Implementierungsdetails entlasten. | Empfohlene strukturelle Überarbeitung |
| 5 | F11 | Zwei fehlende Textverweise ergänzen; erste Nennung von „Abbildung“/„Tabelle“ entsprechend der Vorlage formatieren. | Layoutorientierung |
| 6 | F13 | Architekturgrafik und Crate-Tabelle vor dem jeweils folgenden Abschnitt platzieren. | Layoutorientierung; neu |

**Zurückgestellt:** F01 kann erst nach Zusendung der Erklärung durch das Prüfungsamt abgeschlossen werden. F03 ist im Draft-PDF-Export umgesetzt; die endgültigen PDF- und TeX-Abgabenamen werden erst zur Übergabe geprüft. Beide Punkte gehören derzeit nicht zur Liste der zu überarbeitenden Thesis-Stellen.

Die externen Nachweise und Abstimmungspunkte aus Abschnitt 5 bleiben zusätzlich zu klären. Sie werden nicht als nachgewiesene Verstöße oder als erledigt gewertet.

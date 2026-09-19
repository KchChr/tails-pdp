# Abgleich der Thesis mit dem FTK-Regelwerk

Stand: 19.09.2026. Grundlage: [FTK-Regelwerk](/Users/ck/Code/tails-pdp/thesis/ftk-regelwerk.md), abgeleitet aus dem FTK-Leitfaden vom 15.04.2024.

Geprüft wurden die sieben eingebundenen Kapitel, die LaTeX-Hauptdatei, die verwendeten Literaturangaben und Querverweise sowie ergänzend Text und Schriftgrößen der vorhandenen 79-seitigen PDF. Die README wurde gezielt zur Einordnung der Installationsdokumentation herangezogen. Die PDF wurde nicht neu gebaut; PDF-Seitenangaben beziehen sich auf den vorhandenen Stand mit Titeldatum 18.09.2026. Eine vollständige visuelle Satzkontrolle, erneute fachliche Prüfung aller externen Quellen, ein Code-Audit und Wiederholungen der Linux-Tests waren nicht Bestandteil dieses Abgleichs.

Die Thesis wurde nicht verändert. Zeilennummern beziehen sich auf den geprüften Quellstand.

## Einordnung

Die sieben Hauptkapitel entsprechen grundsätzlich der empfohlenen Argumentationsfolge. Anforderungen besitzen überwiegend Akzeptanzkriterien, die Evaluation greift sie wieder auf, und der Schluss grenzt die Ergebnisse ausdrücklich ein. Die folgenden zwölf Befunde betreffen konkrete Lücken, Abweichungen oder bedingte Konflikte. **Empfehlungen des Leitfadens werden dabei nicht als zwingende Vorschriften behandelt.**

Prioritäten: **hoch** = vor der Abgabe bzw. Ergebnisfreigabe klären; **mittel** = inhaltlich oder strukturell überarbeiten; **niedrig** = formale Angleichung nach Festlegung der Formatvorlage. Die Priorität beschreibt den Überarbeitungsbedarf, nicht den Verbindlichkeitsgrad der Regel.

## 1. Abgabelücken und bedingte Vorgabenkonflikte

### F01 – Erklärung zur selbstständigen Anfertigung fehlt im eingebundenen Dokument

**Bearbeitungsstand 19.09.2026:** Die vom Nutzer vorgegebene Erklärung ist inzwischen als eigene, unnummerierte Schlussseite eingebunden. Felder für Ort, Datum und Unterschrift sind vorhanden; die persönliche Unterzeichnung bleibt für die Abgabe erforderlich. Der folgende Befund dokumentiert den ursprünglichen Prüfstand.

- **Priorität:** hoch vor Abgabe.
- **Regel:** A01, Vorgabe; Leitfaden S. 10.
- **Fundstelle:** [thesis.tex:25](/Users/ck/Code/tails-pdp/thesis/thesis.tex:25) bis Dokumentende, insbesondere [thesis.tex:41](/Users/ck/Code/tails-pdp/thesis/thesis.tex:41).
- **Befund:** Die Hauptdatei bindet Titel, Inhaltsverzeichnis, sieben Kapitel und Literaturverzeichnis ein. Eine Erklärung zur selbstständigen Anfertigung ist nicht eingebunden; auch die vorhandene PDF endet mit dem Literaturverzeichnis.
- **Konflikt:** Der Leitfaden verlangt die ausgefüllte und individuell unterschriebene Erklärung bei Abgabe. Die derzeitige PDF allein enthält diesen Bestandteil nicht.
- **Korrektur:** Die tatsächlich vom Prüfungsamt bereitgestellte Erklärung in die finale Abgabe aufnehmen bzw. nach dessen Vorgaben beifügen. Eine möglicherweise separat vorhandene Erklärung wurde nicht geprüft; der Befund behauptet nicht, dass sie außerhalb der Thesis fehlt.

### F02 – Numerische Zitate kollidieren mit der Sonderregel bei Betreuung durch Prof. Heutelbeck

**Bearbeitungsstand 19.09.2026:** Die Anwendbarkeit von Q05 wurde vom Nutzer bestätigt. Die zentrale Zitierkonfiguration wurde auf `biblatex` mit `style=alphabetic` und Biber umgestellt. Zitate und Literaturverzeichnis verwenden automatisch erzeugte, eindeutige Kürzel; die vorhandenen Zitierbefehle bleiben über den Kompatibilitätsmodus erhalten. Der folgende Befund dokumentiert den ursprünglichen Prüfstand.

- **Priorität:** hoch, falls die Sonderregel anwendbar ist.
- **Regel:** Q05, bedingte Vorgabe; Q04, konsistenter Stil; Leitfaden S. 9.
- **Fundstelle:** [thesis.tex:18](/Users/ck/Code/tails-pdp/thesis/thesis.tex:18) und [thesis.tex:43](/Users/ck/Code/tails-pdp/thesis/thesis.tex:43).
- **Befund:** `natbib` verwendet `numbers,square,sort&compress`, der Bibliographiestil ist `plainnat`. Die PDF zeigt entsprechend numerische Literaturverweise wie `[28]`.
- **Konflikt:** Für Arbeiten bei Prof. Heutelbeck verlangt der Leitfaden Kürzel. Ohne diese Betreuungsvoraussetzung sind Nummern nach § 2.2.9 grundsätzlich erlaubt. Die Betreuung ist aus der Hauptdatei nicht belegbar; deshalb kein unbedingter Verstoß.
- **Korrektur:** Anwendbarkeit und genaue Kürzelform klären und gegebenenfalls Zitat- und Bibliographiestil zusammen umstellen. Nicht allein den Kommentar „klassischer Stil für Autor–Jahr“ ändern; er steuert die Ausgabe nicht.

### F03 – Dateinamen entsprechen noch nicht der vorgesehenen Abgabebenennung

- **Priorität:** hoch vor Übergabe, für Arbeitsstände unkritisch.
- **Regel:** A05, Vorgabe; Leitfaden S. 12–13.
- **Fundstelle:** [thesis.tex](/Users/ck/Code/tails-pdp/thesis/thesis.tex) und [thesis.pdf](/Users/ck/Code/tails-pdp/thesis/thesis.pdf).
- **Befund:** Hauptdatei und PDF heißen `thesis.tex` und `thesis.pdf`. Der Name des Studierenden fehlt in beiden Dateinamen; im PDF-Dateinamen fehlt außerdem der Arbeitstitel.
- **Konflikt:** Der Leitfaden fordert die identifizierbare Benennung der übergebenen Dateien. Für einen internen Build oder einen Zeitstempel-Draft ist daraus kein eigenständiger Verstoß abzuleiten.
- **Korrektur:** Für die finale Übergabe einen Namen wie `thesis_koch_attribute_stream_based_access_control_im_linux_kernel.pdf` vorsehen und auch die übergebene TeX-Hauptdatei entsprechend benennen. Build-Konfigurationen bei einer tatsächlichen Umbenennung mitführen.

## 2. Inhaltliche und strukturelle Konflikte

### F04 – OA-03 bewertet eine Messung als Erfüllung einer nicht operationalisierten Qualitätsforderung

- **Priorität:** mittel.
- **Regel:** W06, Empfehlung; W10 und W11, abgeleitete Prüfregeln; Leitfaden S. 3–4 und 8.
- **Fundstellen:** [03-anforderungsanalyse.tex:92](/Users/ck/Code/tails-pdp/thesis/sections/03-anforderungsanalyse.tex:92), [06-evaluation.tex:530](/Users/ck/Code/tails-pdp/thesis/sections/06-evaluation.tex:530), [06-evaluation.tex:561](/Users/ck/Code/tails-pdp/thesis/sections/06-evaluation.tex:561).
- **Befund:** OA-03 fordert, kontrollierte Zugriffe nicht „unverhältnismäßig“ zu verlangsamen. Das Akzeptanzkriterium verlangt lediglich die Betrachtung der Ausführungszeit. Die Evaluation erklärt zutreffend, dass keine Latenzgrenze festgelegt wurde, bewertet OA-03 aber als erfüllt, weil Aufwand und Latenzen gemessen wurden.
- **Konflikt:** Damit ist das Akzeptanzkriterium erfüllt, die übergeordnete Aussage zur Verhältnismäßigkeit jedoch nicht entschieden. Die Erfolgsaussage ist stärker als der definierte Nachweis.
- **Korrektur:** Entweder OA-03 ausdrücklich als Anforderung zur Performance-Charakterisierung formulieren oder die Bewertung trennen: „quantitativ untersucht; Angemessenheit mangels vorab begründetem Maßstab nicht bewertet“. Keinen nachträglich an die Messwerte angepassten Grenzwert als ursprüngliches Kriterium ausgeben.

### F05 – Aussagen zur Generationskonsistenz sind nicht durchgängig auf dieselbe Garantie begrenzt

**Bearbeitungsstand 19.09.2026:** Die vier vom Nutzer freigegebenen Ersatztexte wurden in Kapitel 4 und 5 übernommen. Die Darstellung unterscheidet nun zwischen vollständiger Vorbereitung vor der Aktivierung und der nicht garantierten unveränderten Lesesicht bei erneuter Verwendung einer Bank. Der folgende Befund dokumentiert den ursprünglichen Prüfstand.

- **Priorität:** mittel.
- **Regel:** W11, abgeleitete Prüfregel; Leitfaden S. 3 und 8.
- **Fundstellen:** [04-konzeption.tex:88](/Users/ck/Code/tails-pdp/thesis/sections/04-konzeption.tex:88), [04-konzeption.tex:398](/Users/ck/Code/tails-pdp/thesis/sections/04-konzeption.tex:398), [04-konzeption.tex:429](/Users/ck/Code/tails-pdp/thesis/sections/04-konzeption.tex:429), [05-entwurf-und-umsetzung.tex:208](/Users/ck/Code/tails-pdp/thesis/sections/05-entwurf-und-umsetzung.tex:208).
- **Befund:** Der Policy-Datenfluss grenzt korrekt ein, dass das Zwei-Bank-Verfahren allein keine unveränderte Lesesicht über mehrere aufeinanderfolgende Generationenwechsel garantiert. Später heißt es dagegen, der Kernel werte „entweder die alte oder die neue Generation“ aus. Der Umsetzungstext erklärt pauschal, eine teilweise geschriebene Policy-Menge werde vom eBPF-Programm nicht ausgewertet.
- **Konflikt:** Ohne erneute Einschränkung können diese Formulierungen als vollständige Lesekonsistenzgarantie verstanden werden. Die zuvor genannte Grenze geht dabei verloren. Dieser Befund betrifft die widersprüchliche Reichweite der Darstellung; es wurde hierfür kein neuer Laufzeitfehler nachgewiesen.
- **Korrektur:** Einheitlich die tatsächlich beschriebene Garantie benennen: Aktivierung erst nach vollständigem Schreiben; keine allgemeine Garantie einer unveränderlichen Lesesicht über mehrere Updates. Stärkere Aussagen nur mit den dafür nötigen Voraussetzungen und Nachweisen treffen.

### F06 – Kapitel 4 enthält konkrete Implementierungsdetails, die Kapitel 5 bereits behandelt

- **Priorität:** mittel.
- **Regel:** W05 und W08, Empfehlungen; Leitfaden S. 3–4.
- **Fundstellen:** [04-konzeption.tex:100](/Users/ck/Code/tails-pdp/thesis/sections/04-konzeption.tex:100), [04-konzeption.tex:370](/Users/ck/Code/tails-pdp/thesis/sections/04-konzeption.tex:370), [04-konzeption.tex:558](/Users/ck/Code/tails-pdp/thesis/sections/04-konzeption.tex:558), [04-konzeption.tex:617](/Users/ck/Code/tails-pdp/thesis/sections/04-konzeption.tex:617).
- **Befund:** Die Konzeption benennt die Rust-Funktion `PolicyTime::from_unix_seconds`, das Ein-Sekunden-Intervall, `inotify` und die konkrete 100-ms-Verzögerung, einzelne Map-Namen, Kernelstrukturfelder `i_ino`/`s_dev` sowie den `ptrace`-basierten `close`-Aufruf auf x86_64. Kapitel 5 beschreibt dieselben technischen Mechanismen erneut, etwa [05-entwurf-und-umsetzung.tex:270](/Users/ck/Code/tails-pdp/thesis/sections/05-entwurf-und-umsetzung.tex:270) und [05-entwurf-und-umsetzung.tex:346](/Users/ck/Code/tails-pdp/thesis/sections/05-entwurf-und-umsetzung.tex:346).
- **Konflikt:** Die empfohlene Trennung zwischen konzeptioneller Modellbildung und technischer Umsetzung wird dadurch unscharf.
- **Korrektur:** In Kapitel 4 Zuständigkeiten, Datenflüsse, Konsistenzmodell, fachliche Entscheidungen und begründete Alternativen behalten. Funktions-/Feldnamen, feste Intervalle und konkrete Systemaufrufmechanik in Kapitel 5 bündeln. Da eBPF-LSM Teil der Forschungsfrage ist, muss die Konzeption nicht künstlich jeden Technologiebezug verlieren.

### F07 – Forschungsstand enthält Grundlagen und Abgrenzungen, aber wenig vergleichende Einordnung vorhandener Lösungen

- **Priorität:** mittel.
- **Regel:** W03, Empfehlung; Leitfaden S. 3–4.
- **Fundstellen:** [02-grundlagen.tex:51](/Users/ck/Code/tails-pdp/thesis/sections/02-grundlagen.tex:51), [02-grundlagen.tex:121](/Users/ck/Code/tails-pdp/thesis/sections/02-grundlagen.tex:121), [02-grundlagen.tex:200](/Users/ck/Code/tails-pdp/thesis/sections/02-grundlagen.tex:200), [04-konzeption.tex:259](/Users/ck/Code/tails-pdp/thesis/sections/04-konzeption.tex:259).
- **Befund:** ASBAC/SAPL, Usage Control und XACML werden eingeordnet. SELinux, Smack, AppArmor und TOMOYO erscheinen vor allem als Beispiele; Aya, libbpf und BCC als Werkzeuge. Ein zusammenhängender Vergleich vorhandener Lösungen hinsichtlich dynamischer Attribute, fortdauernder Autorisierung und Linux-Durchsetzung fehlt. Teile der Abgrenzung zu klassischen LSM stehen erst bei den Entwurfsentscheidungen.
- **Konflikt:** Die Grundlagen sind vorhanden, die im Leitfaden verlangte Perspektive auf bestehende Arbeiten und konkurrierende Lösungsansätze ist jedoch nur teilweise ausgearbeitet. Die Überschrift „Grundlagen“ ist für sich genommen kein Verstoß.
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

### F09 – Titelblatt und Inhaltsverzeichnis haben die falsche Seitennummerierung

**Bearbeitungsstand 19.09.2026:** Titelblatt ohne sichtbare Seitenzahl, römische Nummerierung des Inhaltsverzeichnisses und arabische Nummerierung ab Seite 1 der Einleitung sind umgesetzt. Der folgende Befund dokumentiert den ursprünglichen Prüfstand.

- **Priorität:** niedrig; vor finalem Satz korrigieren, sofern die Orientierung gilt.
- **Regel:** Regelwerk § 3, Seitennummerierung; Leitfaden S. 6–7.
- **Fundstelle:** [thesis.tex:27](/Users/ck/Code/tails-pdp/thesis/thesis.tex:27) bis [thesis.tex:35](/Users/ck/Code/tails-pdp/thesis/thesis.tex:35); PDF-Seiten 1–5.
- **Befund:** Die Hauptdatei setzt weder einen leeren Seitenstil für das Titelblatt noch eine römische Nummerierung der Verzeichnisse. Die vorhandene PDF zeigt auf dem Titelblatt `1`, im Inhaltsverzeichnis arabische Zahlen ab `2` und beginnt die Einleitung mit `5`.
- **Konflikt:** Der Leitfaden sieht ein unnummeriertes Deckblatt, römische Verzeichnisse und anschließend arabisch nummerierten Haupttext vor.
- **Korrektur:** Titelblatt ohne sichtbare Seitenzahl ausgeben; Verzeichnisse römisch nummerieren; vor der Einleitung auf arabische Nummerierung wechseln.

### F10 – Drei Tabellenbeschriftungen stehen unterhalb statt oberhalb der Tabelle

**Bearbeitungsstand 19.09.2026:** Die drei Tabellenbeschriftungen in Kapitel 5 wurden zusammen mit ihren Labels oberhalb der Tabellenkörper platziert. Der folgende Befund dokumentiert den ursprünglichen Prüfstand.

- **Priorität:** niedrig.
- **Regel:** Regelwerk § 3, Abbildungen und Tabellen; Leitfaden S. 7.
- **Fundstellen:** [05-entwurf-und-umsetzung.tex:48](/Users/ck/Code/tails-pdp/thesis/sections/05-entwurf-und-umsetzung.tex:48), [05-entwurf-und-umsetzung.tex:149](/Users/ck/Code/tails-pdp/thesis/sections/05-entwurf-und-umsetzung.tex:149), [05-entwurf-und-umsetzung.tex:242](/Users/ck/Code/tails-pdp/thesis/sections/05-entwurf-und-umsetzung.tex:242).
- **Befund:** Bei Crate-Übersicht, Map-ABI und Policy-Beispiel folgt `\caption` auf `\end{tabular}`. In Kapitel 6 stehen Tabellenbeschriftungen dagegen bereits oberhalb des Tabellenkörpers.
- **Konflikt:** Die Orientierung verlangt Tabellenüberschriften und Abbildungsunterschriften; zusätzlich ist die aktuelle Tabellenformatierung uneinheitlich.
- **Korrektur:** Die drei Tabellenbeschriftungen samt zugehörigem Label vor den Tabellenkörper verschieben.

### F11 – Zwei Darstellungsobjekte besitzen keinen ausdrücklichen Textverweis

- **Priorität:** niedrig.
- **Regel:** Regelwerk § 3, Bezugnahme auf Abbildungen und Tabellen; Leitfaden S. 7.
- **Fundstellen:** [04-konzeption.tex:68](/Users/ck/Code/tails-pdp/thesis/sections/04-konzeption.tex:68), [06-evaluation.tex:438](/Users/ck/Code/tails-pdp/thesis/sections/06-evaluation.tex:438).
- **Befund:** Die Labels `fig:konzeption-architektur` und `tab:funktionale-ergebnisse` sind definiert, werden aber im eingebundenen Text nicht referenziert. Die umliegenden Absätze behandeln den jeweiligen Inhalt, nennen jedoch die Abbildung bzw. Ergebnistabelle nicht ausdrücklich.
- **Konflikt:** Die geforderte Platzierung nach der ersten Bezugnahme ist damit nicht eindeutig nachvollziehbar.
- **Korrektur:** Unmittelbar vorher je einen inhaltlich passenden Satz mit Abbildungs-/Tabellenverweis ergänzen. Die Orientierung zur Fettschrift bei der ersten Erwähnung wird auch bei vorhandenen Verweisen, beispielsweise [05-entwurf-und-umsetzung.tex:18](/Users/ck/Code/tails-pdp/thesis/sections/05-entwurf-und-umsetzung.tex:18), noch nicht umgesetzt; gegebenenfalls einheitlich behandeln.

### F12 – Standardformatierung weicht bei Schriftgrößen, Absätzen und Seitenfuß ab

**Bearbeitungsstand 19.09.2026:** Überschriften (16/14/12 pt, vierte Ebene 12 pt kursiv und abgesetzt), Absatzabstände, Tabellen und Beschriftungen (10 pt) sowie Seitenzahlen rechts unten mit Trennlinie sind zentral konfiguriert. Die bestehende Times-orientierte LaTeX-Schrift newtx bleibt erhalten; eine Umstellung auf die konkrete Schrift Times New Roman war nicht Teil dieser Korrektur. Der folgende Befund dokumentiert den ursprünglichen Prüfstand.

- **Priorität:** niedrig.
- **Regel:** Regelwerk § 3, Text, Überschriften, Kopf-/Fußzeilen und Tabellen; Leitfaden S. 6–7.
- **Fundstellen:** [thesis.tex:1](/Users/ck/Code/tails-pdp/thesis/thesis.tex:1) bis [thesis.tex:22](/Users/ck/Code/tails-pdp/thesis/thesis.tex:22), [04-konzeption.tex:149](/Users/ck/Code/tails-pdp/thesis/sections/04-konzeption.tex:149), [05-entwurf-und-umsetzung.tex:22](/Users/ck/Code/tails-pdp/thesis/sections/05-entwurf-und-umsetzung.tex:22), [06-evaluation.tex:86](/Users/ck/Code/tails-pdp/thesis/sections/06-evaluation.tex:86).
- **Befund:** Die 12-pt-`article`-Klasse verwendet weitgehend ihre Standardformatierung. Hauptüberschriften sind nominal 17,28 pt statt der empfohlenen 16 pt groß; in der PDF erscheinen sie entsprechend mit rund 17,22 PDF-Punkten. Beschriftungen erscheinen etwa in Fließtextgröße 12 pt statt 10 pt. Tabellen in Kapitel 5 verwenden überwiegend `\small` (bei dieser Klasse 11 pt), Kapitel 6 überwiegend die normale Textgröße. `\paragraph` bleibt standardmäßig fett und im Absatz laufend statt einer abgesetzten kursiven vierten Ebene. Eine Leerzeile im TeX-Quelltext erzeugt hier keinen vollen Leerzeilenabstand zwischen Absätzen. Die Seitenzahl steht im Standard-Seitenfuß mittig; eine Trennlinie ist nicht konfiguriert.
- **Konflikt:** Dies entspricht nicht der detaillierten Layoutorientierung des Regelwerks. Die Seitenränder 4/2/3/3 cm sind dagegen bereits passend eingestellt.
- **Korrektur:** Nach Festlegung der verbindlichen Vorlage Überschriften, Absätze, Tabellen, Beschriftungen und Seitenstil zentral konfigurieren. `newtxtext` ist eine Times-orientierte LaTeX-Schrift, nicht wörtlich Times New Roman; die Zulässigkeit dieser Umsetzung ebenfalls mit der Formatvorlage klären. Die Schriftwahl allein wird hier nicht als zusätzlicher sicherer Verstoß gewertet.

## 4. Offene Nachweise – keine belegten Verstöße

| Bereich | Beobachtung und Grenze der Prüfung | Nächster sinnvoller Schritt |
| --- | --- | --- |
| Installations- und Programmierhandbuch (S02/S03, A03) | [Kapitel 5.10](/Users/ck/Code/tails-pdp/thesis/sections/05-entwurf-und-umsetzung.tex:389) beschreibt Build und Start; die [README](/Users/ck/Code/tails-pdp/README.md:3) enthält Voraussetzungen und Bedienhinweise. Ein gesondertes finales Handbuchpaket ist damit noch nicht belegt. Die README nennt unversioniertes Nightly, während die Evaluation einen datierten Stand dokumentiert. Daraus folgt nicht, dass extern keine Handbücher existieren. | Aus vorhandener Dokumentation eine eindeutige Anleitung für das tatsächlich evaluierte Zielsystem zusammenstellen, einschließlich Kernel-/BTF-/BPF-LSM-Voraussetzungen und Berechtigungen. Schnittstellendokumentation als Programmierhandbuch identifizierbar machen. Die Grenze von drei Arbeitsschritten erst am finalen Ablauf bewerten. |
| Abbildungsherkunft (Q09–Q11) | Die Crate-Grafik ist als eigene Darstellung bezeichnet; zur Architekturgrafik liegt eine bearbeitbare `.drawio`-Datei vor. Daraus lässt sich keine fremde Urheberschaft und folglich auch keine fehlende Rechteklärung ableiten. | Herkunft prüfen, falls Fremdmaterial übernommen wurde; nur dann die vorgeschriebene Dokumentation der Nutzungsrechte verlangen. |
| Literaturformat (Q08) | `plainnat` gibt Namen nicht in der im Orientierungsabschnitt beschriebenen Großschreibung aus. Das Regelwerk kennzeichnet diese Formatdetails wegen widersprüchlicher Leitfadenbeispiele ausdrücklich als Abstimmungspunkt. | Mit F02 gemeinsam einen einheitlichen Literaturstil festlegen. |
| Abbildungs-/Tabellen-/Abkürzungsverzeichnisse | [thesis.tex:31](/Users/ck/Code/tails-pdp/thesis/thesis.tex:31) erzeugt nur das Inhaltsverzeichnis. Der Leitfaden beschreibt weitere Verzeichnisse, legt aber nicht eindeutig fest, dass jede Arbeit alle davon enthalten muss. | Erforderliche Verzeichnisse mit der Formatvorlage klären; nicht allein aus ihrer Erwähnung eine allgemeine Pflicht ableiten. |
| Planung und Betreuung (P01–P09) | Exposéfreigabe, Anmeldung, verbindlicher Titel, Betreuungstermine und Vereinbarungen sind aus den sieben Kapiteln nicht verifizierbar. | Anhand der tatsächlichen Studien- und Betreuungsunterlagen prüfen. |
| Finale Übergabe (S07–S10, A02–A07) | Cloud-Ablage, Lizenzabsprachen, vollständige Binär-/Abhängigkeitspakete, unterschriebene Dokumente, Submission-Tag und Kolloquium wurden nicht als externe Zustände geprüft. | Vor Abgabe den konkreten Übergabeumfang und die aktuell geltenden Prüfungsamtsvorgaben kontrollieren. |

## 5. Geprüfte Punkte ohne festgestellten Regelkonflikt

- Die sieben Hauptkapitel folgen der empfohlenen Grundstruktur; eine Umbenennung von „Grundlagen“ in „State of the Art“ ist nicht an sich erforderlich.
- Forschungsfrage, Zielsetzung und Prototypgrenzen sind in der Einleitung vorhanden. Der Schluss beantwortet die Frage und behandelt Grenzen sowie weitere Arbeiten.
- Funktionale, operative und entwicklungsbezogene Anforderungen sind in Kapitel 3 gebündelt. Kapitel 6 enthält eine eigene Anforderungsbewertung; F04 und F08 betreffen konkrete Einschränkungen dieser Bewertung.
- Alle **38 verschiedenen zitierten Literaturkennungen** sind in `literatur.bib` vorhanden und erscheinen im bestehenden Literaturverzeichnis. Kein fehlender Bibliographieeintrag wurde festgestellt. Das ist keine Bestätigung der inhaltlichen Tragfähigkeit jeder Quelle.
- Alle verwendeten LaTeX-Verweise besitzen ein definiertes Ziel. F11 betrifft den umgekehrten Fall: vorhandene Darstellungen ohne ausdrücklichen Verweis.
- Der Text zeigt kurze Policy-/Attributbeispiele, keine langen vollständigen Programmabdrucke. Kein belegter Konflikt mit W09.
- Hauptkapitel werden durch Seitenumbrüche getrennt. Die Seitenränder entsprechen den genannten Werten.
- Die Evaluation benennt Aussagegrenzen, die geringe Zahl bestimmter Wiederholungen, verbleibende Race-Risiken und die begrenzte Übertragbarkeit. Der Schluss behauptet weder allgemeine Race-Freiheit noch Echtzeit- oder Produktionstauglichkeit.

## 6. Empfohlene Reihenfolge der Bearbeitung

1. F04/F05 klären, damit Anforderungsbewertung und Konsistenzbehauptungen inhaltlich präzise sind.
2. F06–F08 bearbeiten: Kapitelzuständigkeiten, vergleichende Einordnung und qualitative Bewertung schärfen.
3. F02 sowie die offene Formatvorlage abstimmen; anschließend F09–F12 zentral umsetzen.
4. Für die finale Übergabe F01/F03 und die externen Abgabenachweise abschließen.

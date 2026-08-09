# Priorisierte To-do-Liste vor der Abgabe

## P0 – unbedingt beheben

1. **Abschnitt 2.3 und Related Work:** ASBAC-Primärliteratur (insbesondere SACMAT 2021, DOI `10.1145/3450569.3464397`) lesen, korrekt darstellen und den pollingbasierten Prototyp vom Publish-/Subscribe-/Decision-Stream-Modell abgrenzen.
2. **Kapitel 1:** Forschungslücke, Scope/Nicht-Ziele, Methode und konkrete Eigenbeiträge ergänzen; Forschungsfrage ggf. auf `file_open` und die teilweise Userspace-basierte Nachkontrolle präzisieren.
3. **FA-07:** „unmittelbar beenden“ durch eine empirisch prüfbare best-effort/zeitgebundene Formulierung ersetzen oder Implementierung entsprechend härten; FD-Reuse, Threads, Duplikate, Vererbung, `mmap` und nicht attachbare Prozesse explizit behandeln.
4. **UID-Konsistenz (inhaltlich umgesetzt):** Real UID ist für beide Pfade belegt, in der Thesis definiert und im Userspace unit-getestet. Vor Abschluss der Evaluation noch den vorgesehenen privilegierten Kernel-/Userspace-E2E-Vergleich ausführen und dessen Ergebnis dokumentieren.
5. **Formalia:** Abschnitt 1.4 vervollständigen und den großen TODO-Platzhalter auf PDF-Seite 38 durch eine fertige Abbildung oder eine präzise Tabelle ersetzen.
6. **Kapitel 6:** Anforderungs-Traceability, Messwerte, Baselines, Wiederholungen/Statistik, Revocation-Latenz, Performance, Fehlerfälle und Race-/Grenztests durchführen und dokumentieren.

## P1 – sehr wichtig

7. **Reference Monitor:** TCB und Trust Boundaries vollständig darstellen; `tamper proof`, `always invoked/complete mediation` und `small enough to analyze/test` jeweils am konkreten System bewerten und Claims begrenzen.
8. **Threat Model:** Angreifer, Schutzziele, privilegierte Komponenten, Capabilities, Policy-/Attributdateirechte, bpffs-/Map-Rechte und Ausfallannahmen definieren.
9. **Fail-open/fail-closed:** Fehlerfallmatrix erstellen. Kernel-Tail-Call-Fehler, fehlende Attribute, Loader-/PEP-Ausfall, Scan-/ptrace-Fehler und ungültige Updates getrennt bewerten.
10. **Ressourcen-Semantik:** Festlegen, ob Policies Pfade oder konkrete Device/Inode-Objekte schützen; atomaren Dateiaustausch testen und Reprocessing-Lücke diskutieren.
11. **Stand der Forschung:** UCON/continuity of decision, SAPL/ASBAC, XACML PDP/PEP/PIP/PAP, klassische LSM/MAC-Systeme und verwandte dynamische Linux-Ansätze strukturiert vergleichen.
12. **Titel/Claims:** Klarstellen, dass der neue-Zugriff-PEP im Kernel, die Nachkontrolle bestehender FDs jedoch im Userspace liegt; keine vollständige „ASBAC im Kernel“-Durchsetzung suggerieren.

## P2 – verbessert die Qualität deutlich

13. **Technologieauswahl:** eBPF-LSM, klassisches LSM, fanotify und reine Userspace-Ansätze anhand transparenter Kriterien vergleichen.
14. **Kapiteltrennung:** Kapitel 4 auf Konzept/Alternativen/Konsequenzen, Kapitel 5 auf konkrete Umsetzung/Evidenz reduzieren; Wiederholungen durch Rückverweise ersetzen.
15. **Claims-Audit:** Jede starke Aussage markieren und zuordnen: Quelle, logische Herleitung, Code-Evidenz oder Evaluation. Wörter wie „verhindert“, „muss“, „geeigneter“, „unmittelbar“ und „fail-closed“ gezielt prüfen.
16. **Terminologie:** ASBAC, Stream-Attribut, dynamisches Attribut, Policy, PDP, PEP, Entscheidung und Enforcement konsistent definieren und verwenden.
17. **Abbildungen:** TCB-/Trust-Boundary-Diagramm und vollständigen zeitlichen Datenfluss von Attributänderung bis Entzugsversuch ergänzen.

## P3 – optionaler Feinschliff

18. Formale Hochschulvorgaben für Titelseite, Abstract, Selbstständigkeitserklärung, Sperrvermerk und Metadaten prüfen.
19. Sichtbare PDF-Hyperlink-Rahmen drucktauglich konfigurieren und Bibliografiestil/URL-Darstellung vereinheitlichen.
20. Kleinere Schreibweisen vereinheitlichen (`praktische Einschränkungen`, Stream-Attribut/Streampolicy, Kernelspace-/Userspace-Komposita) und lange Absätze kürzen.

## Empfohlene Bearbeitungsreihenfolge

1. ASBAC-/Related-Work-Korrektur und Scope festlegen.
2. Forschungsfrage, Beiträge und Anforderungen an diesen Scope anpassen.
3. Security-/Code-Inkonsistenzen analysieren, insbesondere UID und Revocation.
4. Evaluation exakt aus den korrigierten Anforderungen ableiten und durchführen.
5. Diskussion/Ausblick und Schluss schreiben.
6. Erst danach Redundanz, Sprache, Abbildungen und Formalia finalisieren.

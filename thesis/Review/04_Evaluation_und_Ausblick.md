# Vorschlag für Kapitel 6 und 7

## 1. Evaluationsfragen

| ID | Frage | Bezug |
|---|---|---|
| EF-1 | Erfüllt der Prototyp jede funktionale Anforderung unter Normalbedingungen? | FA-01 bis FA-12 |
| EF-2 | Stimmen Kernel- und Userspace-PEP für identische Requests und Attribute überein? | Forschungsfrage, FA-05–07 |
| EF-3 | Welche Latenz liegt zwischen Attribut-/Policyänderung und wirksamem Entzugsversuch? | ASBAC-/Revocation-Kernbeitrag |
| EF-4 | Wie verhält sich das System bei ungültigen, fehlenden oder partiell aktualisierten Zuständen? | FA-10/11, Security |
| EF-5 | Welchen Overhead erzeugt der `file_open`-PEP? | OA-03 |
| EF-6 | Wie skalieren Hook-Latenz, Scanzeit und CPU-Last mit Policies, Attributen, Prozessen und FDs? | technische Einschränkungen |
| EF-7 | Welche Umgehungs- und Race-Szenarien bleiben bestehen? | Diskussion/Limitierungen |

## 2. Konkrete Experimente

### E1 – Anforderungs-Traceability

Für jede Anforderung eine Tabellenzeile mit Setup, Eingabe, erwarteter Beobachtung, tatsächlicher Beobachtung, Test-ID und Ergebnis. Nicht nur „Test bestanden“, sondern relevante Log-/Map-/Return-Werte angeben. FA-07 muss vorab realistisch umformuliert werden.

### E2 – Policysemantik

Testmatrix aus Permit/Deny/kein Match, statisch/stream, mehreren Policies, fehlendem Attribut, falschem Typ, Grenzwerten und vier Bedingungen. Deny-overrides und Default-Permit separat prüfen. Kernel- und Userspace-Ergebnis für dieselben Testvektoren vergleichen.

### E3 – Generationen und fehlerhafte Updates

Während paralleler `openat()`-Last Policies/Attribute wiederholt gültig/ungültig wechseln. Erfassen, ob je ein Mischzustand sichtbar wird. Besonders schnelle Updates testen, bei denen eine der zwei Bänke erneut verwendet wird, bevor ein Userspace-Scan abgeschlossen ist.

### E4 – Revocation-Latenz

Zeitpunkte (t_0) Änderung erkannt, (t_1) neue Generation aktiviert, (t_2) Verletzung im Scan erkannt, (t_3) `close` abgeschlossen messen. Mindestens 30–100 Wiederholungen pro Szenario; Median, p95, p99, Minimum/Maximum berichten. Szenarien mit 1/100/1000 Prozessen bzw. steigender FD-Zahl.

### E5 – Revocation-Grenzfälle

- FD wird zwischen Scan und Entzug geschlossen und wiederverwendet.
- Zwei Threads teilen die FD-Tabelle und verändern sie parallel.
- Datei wurde über `dup()` dupliziert bzw. an Kindprozess vererbt.
- Datei ist vor Entzug per `mmap()` abgebildet.
- Ziel ist PID 1, der PEP selbst oder aufgrund von `ptrace`-Regeln nicht attachbar.
- Prozess beendet sich während Attach/Wait.
- Signale treffen während `PTRACE_ATTACH` ein.

Ergebnis darf lauten „nicht zuverlässig unterstützt“; entscheidend ist die ehrliche Einordnung.

### E6 – Credential-Konsistenz

Normale UID sowie kontrolliert unterschiedliche Real/Effective/Saved/Filesystem UIDs verwenden. Der vorhandene Unit-Test belegt, dass der Userspace-PEP das Real-UID-Feld auswählt. Ein privilegiertes Szenario muss zusätzlich zeigen, dass Kernel- und Userspace-PEP dieselbe Real-UID-gefilterte Policy gleich entscheiden. Bis zur tatsächlichen Durchführung ist dies ein geplanter E2E-Nachweis und kein bereits belegtes Ergebnis.

### E7 – Performance von `open/openat`

Baseline ohne geladenes Programm, geladenes Programm ohne passende Policy, 1/8/16 statische Policies, 1/8/16 Stream-Policies mit 1–4 Attributbedingungen. Warm-up, ausreichend viele Iterationen, mehrere unabhängige Läufe, CPU-Pinning soweit sinnvoll. Metriken: ns/Operation, relativer Overhead, CPU-Zeit. Testwerkzeug und Compiler-/Kernelversion dokumentieren.

### E8 – Robustheit und Ausfall

Userspace-PEP stoppen, Attributloader stoppen, Map-Einträge/Generation fehlen lassen (nur isoliertes Testsystem), ungültige Policy, volle Attributmap, fehlende Pin-Rechte, Tail-Call-Setupfehler. Für jeden Fall erwartetes und beobachtetes fail-open/fail-closed Verhalten dokumentieren.

### E9 – Ressourcenlebenszyklus

Geschützte Datei per Rename/atomarem Replace austauschen, Hardlink/Symlink verwenden und Verhalten in Mount-/User-Namespaces untersuchen, soweit Scope. Klar bestimmen, ob Objekt- oder Pfadsemantik vorliegt.

## 3. Mess- und Berichtsqualität

- Zielsystem: Distribution, Kernelversion/-konfiguration (`CONFIG_BPF_LSM`, aktive LSM-Reihenfolge), CPU, RAM, Rust, Aya, Toolchain, Commit-ID.
- Reproduzierbare Befehle, Policies und Rohdaten im Repository referenzieren.
- Für Zeitmessungen Wiederholungszahl, Verteilung und Unsicherheit angeben; nicht nur Einzelwerte.
- Negative Ergebnisse nicht auslassen.
- Tests beweisen keine vollständige Sicherheit; sie liefern Evidenz für definierte Szenarien.

## 4. Empfohlene Tabellen und Diagramme

1. Anforderung → Test → Ergebnis → Evidenz.
2. Fehlerfallmatrix mit Fail-open/Fail-closed.
3. Box-/Violinplot für `openat()`-Latenzen je Policykonfiguration.
4. ECDF oder Boxplot der Revocation-Latenz.
5. Scanzeit/CPU gegen Zahl der Prozesse und FDs.
6. Konsistenzmatrix Kernel-PEP vs. Userspace-PEP.
7. TCB-/Trust-Boundary-Abbildung.

## 5. Vorschlag Kapitel 7 – Diskussion und Ausblick

### 7.1 Zusammenfassung der Antwort auf die Forschungsfrage

Konkrete Antwort: Was wurde prototypisch realisiert, was zeigt die Evaluation, und welche Einschränkungen ergeben sich? Keine bloße Kapitelzusammenfassung.

### 7.2 Einordnung gegenüber ASBAC, UCON und Reference Monitor

Unterschied zwischen Decision Streams und Polling; initiale vs. fortdauernde Autorisierung; Grad der vollständigen Vermittlung; keine Behauptung vollständiger Reference-Monitor-Erfüllung.

### 7.3 Limitierungen der Implementierung

Ein-Sekunden-Polling, `/proc`-Snapshot, FD-Reuse, Threads, `dup`/Vererbung, `mmap`, PID-/Namespace-/ptrace-Grenzen, x86_64-Spezifik, 16 Policies pro Bank, vier Bedingungen, 1024 Attribute, UTC-/Zeitauflösung, Credential-Semantik, Ressourcen-Replacement.

### 7.4 Limitierungen des Ansatzes

Nur `file_open`; kein genereller Entzug bereits vermittelter Kernelobjekte; privilegierter Userspace-PEP und Map-Trust; eBPF-Verifier-/Helper-/Kernelversionsabhängigkeit; Polling-Skalierung.

### 7.5 Validitätsbedrohungen

Ein Zielsystem, synthetische Workloads, begrenzte Policygröße, Messrauschen, fehlender Vergleich mit produktiven MAC-Systemen, Testabdeckung statt Sicherheitsbeweis.

### 7.6 Ausblick

- ereignisgetriebene Decision-/Attribute-Streams statt Polling;
- weitere geeignete LSM-Hooks und Ressourcenarten;
- robustere Revocation-Semantik bzw. kooperative PEPs;
- Capability-Minimierung und gehärtete bpffs-/Policy-Rechte;
- Container, User-/Mount-Namespaces, cgroups;
- umfassendere Policy-Sprache und Indexierung statt linearer 16er-Scans;
- Vergleich mit SAPL/UCON-Architekturen und etablierten Linux-MAC-Systemen;
- persistente, signierte oder attestierte Policies/Attribute.

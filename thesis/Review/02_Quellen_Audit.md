# Quellen-Audit

## 1. Zentrale Quellen und Deckung

Legende: **verifiziert** = Existenz und relevante öffentlich zugängliche Passage geprüft; **plausibel** = bibliografisch/inhaltlich plausibel, aber im Rahmen dieses Audits nicht vollständig satzgenau geprüft; **fehlt** = für die konkrete Kernaussage keine passende Quelle in der Thesis.

| Stelle / Aussage | verwendete Quelle | verfügbar? | Deckung | Qualität | Problem | Empfehlung |
|---|---|---:|---|---|---|---|
| 2.1: drei Reference-Monitor-Eigenschaften | Anderson 1972 | ja, plausibel | grundsätzlich | klassischer Primär-/Tech-Report | Formulierung und Übertragung auf Prototyp nicht satzgenau nachgewiesen | Originalpassage prüfen; Eigenschaftsmatrix ergänzen |
| 2.1: complete mediation | Saltzer/Schroeder 1975 | ja, verifiziert | vollständig für Prinzip | klassischer Peer-Review-Artikel | Quelle belegt Prinzip, nicht dessen Erfüllung durch diesen Prototyp | Claim auf theoretisches Prinzip begrenzen |
| 2.2: ABAC-Definition | NIST SP 800-162, DOI `10.6028/NIST.SP.800-162` | ja, verifiziert | vollständig | autoritativer Standard/Guide | bibliografisches Jahr 2014 ist vertretbar, aktualisierte Fassung 2019 beachten | konkrete Version/Update-Stand konsistent angeben |
| 2.3: Definition ASBAC | Gouglidis et al. 2018 (UseCON) | ja, verifiziert | nur indirekt | wissenschaftliches Paper | Paper behandelt Usage Control/UseCON, nicht die namensgebende ASBAC-Definition | ASBAC-Primärquelle Heutelbeck ergänzen; UCON nur als verwandtes Modell |
| 2.4: PDP/PEP und Policy-Sprache | OASIS XACML 3.0 | ja, verifiziert | grundsätzlich | Primärstandard | XACML trennt mehr Rollen (u. a. PAP/PIP); Übernahme nur als Begriffsrahmen klarer machen | Architekturmodell gezielt und vollständig zitieren |
| 2.6: LSM-Hooks als Sicherheitsframework | Wright et al. 2002 | ja, plausibel | grundsätzlich | peer-reviewte USENIX-Primärquelle | „Reference-Monitor-ähnlich“ ist Interpretation der Thesis | Interpretation kennzeichnen und Grenzen nennen |
| 2.7: BPF-LSM für systemweite MAC/Audit-Policies | Kernel-Doku `prog_lsm` | ja, verifiziert | vollständig | offizielle Primärdokumentation | dokumentiert Fähigkeit, nicht vollständige Sicherheit/Abdeckung | keine stärkere Eigenschaft ableiten |
| 2.7/2.9: Verifier-/Stackgrenzen | Kernel-Doku, Aya Book | ja, plausibel | überwiegend | offizielle Doku/Projektdoku | Versionsabhängige Details; 256-Byte-Aussage bei Tail Calls genau versionsbezogen prüfen | Kernel-/Aya-Version nennen, Originalpassage präzise zitieren |
| 2.8: Maps und Userspace-Austausch | Kernel-Doku / `bpf(2)` | ja, plausibel | vollständig | offizielle Doku/man-pages | kein wesentlicher Mangel | beibehalten |
| 2.12: `/proc/<pid>/fd` und Zugriffsprüfung | `proc_pid_fd(5)` | ja, verifiziert | grundsätzlich | man-pages | Quelle belegt Sichtbarkeit/Berechtigungsprüfung, nicht zuverlässige Revocation | zusätzliche `ptrace(2)`, `dup(2)`, `mmap(2)` und Threads-Quellen nötig |
| 4.6.2: eBPF-LSM sei „geeigneter“ und schneller testbar | Kernel-Doku/Aya | ja | zu weit interpretiert | Doku | keine vergleichende Evidenz für „geeigneter“ oder Entwicklungszeit | als eigene Entscheidung markieren und Kriterienvergleich liefern |
| 4.6.7: Double Buffering verhindere Teilzustände | keine direkte Quelle | – | nur durch Design/Code plausibel | Eigenentwurf | zwei Bänke liefern keine beliebig lange Snapshot-Isolation; Wiederverwendung kann laufende Scans treffen | formales Invariant + Concurrency-Test; Claim abschwächen |
| 4.6.12: Device/Inode näher an Dateiidentität | keine direkte Kernquelle | – | plausibel | Eigenargument | Lebenszyklus, Bind Mounts/Namespaces und Replacement-Semantik fehlen | VFS-/inode-Primärdoku oder man-pages, klare Scope-Grenze |
| 5.7.3: gezielter FD-Entzug per `ptrace` | keine Quelle | – | durch Code ersichtlich, aber nicht als Garantie | Eigenimplementierung | `ptrace` ist threadbezogen; Attach-/Signal-/Race-Semantik fehlt | `ptrace(2)`, `close(2)`, `dup(2)`, `mmap(2)` zitieren |
| 5.9.3: Fail-closed | Kernelpfad durch Code | ja | nur teilweise | Eigenimplementierung | gilt nicht für Userspace-PEP und fehlende Attribute | komponentenbezogene Fehlerfallmatrix |

## 2. Besonders gravierende Quellenlücke: ASBAC

Die Recherche ergab eine direkt einschlägige Publikation:

- Dominic Heutelbeck, *Demo: Attribute-Stream-Based Access Control (ASBAC) with the Streaming Attribute Policy Language (SAPL)*, SACMAT 2021, DOI `10.1145/3450569.3464397`.

Die öffentlich auffindbare Zusammenfassung beschreibt ASBAC als Publish-/Subscribe-Ansatz, bei dem eine Subscription einen Strom aktualisierter Entscheidungen aufgrund von Attribut-, Policy- und PDP-Konfigurationsänderungen erzeugt. Das ist näher am Thema als das derzeit verwendete UseCON-Paper und zugleich wichtig, weil der hier untersuchte Prototyp **keinen Decision Stream**, sondern periodische lokale Neubewertung implementiert. Die Quelle sollte nicht lediglich ergänzt, sondern als Ausgangspunkt einer begrifflichen Abgrenzung verwendet werden.

## 3. Fehlende Belege

| Stelle | Aussage | Warum Beleg notwendig? | empfohlene Quellenart / Suchrichtung |
|---|---|---|---|
| 1.1 | LSM stelle Mechanismen „mittels ABAC“ bereit | LSM ist modellneutral; Aussage ist wahrscheinlich sachlich zu eng | offizielle LSM-Doku; Formulierung korrigieren statt Beleg erzwingen |
| 2.3 | ASBAC sei die dargestellte Erweiterung von ABAC | namensgebender wissenschaftlicher Begriff | SACMAT-ASBAC-Paper; SAPL-Architektur als ergänzende Projektdoku |
| 2.5 | Userspace-Parsing sei leichter/sicherer und Kernelcode gefährde Gesamtsystem | allgemein plausibel, aber sicherheitsrelevante Begründung | Kernel-Dokumentation bzw. belastbare OS-/Security-Literatur |
| 4.1 | freie Policy-Sprache könne im Kernel nicht ausgewertet werden | „nicht möglich“ ist zu absolut; es ist eine Design-/Komplexitätsentscheidung | als eigene Scopeentscheidung formulieren; Verifier-Doku für Grenzen |
| 4.6.2 | eBPF-LSM sei für den Prototyp geeigneter | zentrale Technologieentscheidung | Kriterienbasierter eigener Vergleich plus Primärdoku |
| 4.6.7 | Generationenmodell verhindere Teilzustände | Nebenläufigkeits-/Atomizitätsclaim | Code-Invariant, Kernel-Map-Semantik, experimenteller Nachweis |
| 4.6.13–14 | konkreter FD werde zuverlässig entzogen | Security-/Korrektheitsclaim mit Race-Risiken | `ptrace(2)`, `close(2)`, `/proc`-Doku; eigene Race-Tests |
| 5.7.1 | dieselbe Repräsentation in Kernel und Userspace | UID-/Command-/Device-Semantik muss identisch sein | Aya-API-/Helper-Doku und Linux `/proc`-Doku; E2E-Nachweis |
| 5.9.3 | System verhalte sich fail-closed | hängt stark vom Fehlerfall ab | eigene Fehlerfallmatrix und Tests, ggf. Security-Engineering-Literatur |

## 4. Bibliografische/formale Beobachtungen

- Die Bibliografie enthält mehrere ungenutzte oder thematisch randständige Einträge (z. B. Kernel-FFI, Rust-in-Kernel-Seiten, SAPL-Webseite). Nur tatsächlich zitierte Literatur sollte im finalen Verzeichnis erscheinen, sofern der verwendete Stil dies nicht ohnehin filtert.
- Zugriffsdaten und Jahresfelder von laufend aktualisierten Dokumentationsseiten werden uneinheitlich über `@online`/`@misc`, `urldate`/`note` modelliert. Einheitlich formatieren.
- Offizielle Kernel-Dokumentation ist für konkrete API-/Mechanismusaussagen angemessen, ersetzt aber keine wissenschaftliche Related-Work-Diskussion.
- GitHub-Projektseiten für libbpf/BCC sind als Projektbeleg akzeptabel, aber schwach für vergleichende Qualitätsaussagen.
- Der ASBAC-Webeintrag `SAPL` mit Autor „Anonym“ ist als zentrale Quelle ungeeignet; bevorzugt werden sollte das Konferenzpaper mit DOI.

## 5. Verifikationsgrenze

Direkt geprüft wurden insbesondere die öffentlich verfügbaren Seiten von NIST SP 800-162, OASIS XACML 3.0, Linux BPF-LSM, Saltzer/Schroeder, das arXiv-Metadatum zum UseCON-Paper, die ASBAC-SACMAT-Metadaten sowie `ptrace(2)`. Bei den übrigen Quellen bedeutet „plausibel“ ausdrücklich nicht, dass jede konkrete Thesis-Aussage in der Originalquelle satzgenau gefunden wurde. Vor Abgabe sollte für jede zentrale Behauptung ein manueller Passage-zu-Claim-Abgleich erfolgen.

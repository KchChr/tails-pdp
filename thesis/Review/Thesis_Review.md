# Kritische Zwischenbegutachtung der Bachelorarbeit

**Arbeit:** *Attribute Stream-Based Access Control im Linux-Kernel*  
**Begutachtungsstand:** Repository und PDF vom 8. August 2026  
**Charakter:** Zwischenbewertung; Kapitel 6 und 7 werden nicht wegen ihrer derzeitigen Unvollständigkeit abgewertet.  
**Prüfgrundlage:** `thesis/thesis.pdf` (58 Seiten), LaTeX-Quellen, `literatur.bib`, Rust-/eBPF-Implementierung, Tests und Projektdokumentation.

## 1. Executive Summary

Der bisherige Stand bildet eine technisch substanzielle Grundlage für eine Bachelorarbeit. Positiv sind vor allem die konkrete Forschungsfrage, der funktionsfähige und nicht triviale Prototyp, die nachvollziehbare Zerlegung in Loader, Kernelspace-PEP, Userspace-PEP und Administrationstool sowie die vergleichsweise offene Beschreibung mehrerer Implementierungsgrenzen. Die Kapitel 3 bis 5 zeigen erkennbare Eigenleistung und eine intensive Auseinandersetzung mit eBPF-LSM, Map-ABIs, Generationenwechseln und der nachträglichen Behandlung offener File Descriptors.

In der jetzigen Fassung gefährden jedoch mehrere Punkte eine gute Bewertung:

1. **Der zentrale Begriff ASBAC ist wissenschaftlich falsch bzw. unvollständig eingeordnet.** Abschnitt 2.3 definiert ASBAC im Wesentlichen selbst und stützt die Einordnung nur über Usage Control. Es existiert aber einschlägige, unmittelbar namensgleiche ASBAC-Literatur (u. a. Heutelbeck, SACMAT 2021, DOI `10.1145/3450569.3464397`). Diese beschreibt ein Publish-/Subscribe-Modell mit fortlaufenden Entscheidungen. Der eigene pollingbasierte Ansatz muss dagegen abgegrenzt werden. Das ist derzeit der schwerwiegendste wissenschaftliche Mangel.
2. **Die Reference-Monitor-Argumentation ist nicht bis zur konkreten TCB und Hook-Abdeckung geführt.** `file_open` vermittelt nur neue Öffnungen, der Userspace-PEP pollt periodisch und kann nicht alle fortdauernden Nutzungen zuverlässig entziehen. Daher darf für das Gesamtsystem weder vollständige Vermittlung noch Manipulationssicherheit suggeriert werden.
3. **FA-07 verspricht „unmittelbares“ Beenden, der Code scannt im Ein-Sekunden-Takt.** Zwischen Erkennung und `ptrace`-Eingriff bestehen TOCTTOU- und FD-Reuse-Risiken. Duplizierte oder vererbte Deskriptoren, `mmap`, nicht attachbare Prozesse, Threads und PID 1 werden nicht vollständig erfasst bzw. entzogen. Die Thesis benennt einige, aber nicht alle Konsequenzen.
4. **Kernel- und Userspace-PEP können unterschiedliche Subjekt-UIDs verwenden.** Der Kernelpfad nutzt `ctx.uid()`, der Userspace-PEP liest aus `/proc/<pid>/status` den ersten `Uid:`-Wert, also die Real UID. Für setuid-/credential-changing Prozesse kann damit dieselbe Policy unterschiedlich ausgewertet werden. Das ist vor Abgabe entweder zu korrigieren oder als Scope-/Sicherheitsgrenze präzise zu untersuchen.
5. **Die Evaluation muss weit über das vorhandene Testskript hinausgehen.** Notwendig sind insbesondere Anforderungs-Traceability, Revocation-Latenz, Negativ-/Fehlerfälle, UID-Sonderfälle, FD-Reuse/Parallelität, Skalierung und `open()`-Overhead. Ein funktionierender Happy Path genügt nicht zum Tragen der Sicherheits- und Performanceaussagen.
6. **Es bestehen zwei offensichtliche formale Abgabe-Blocker:** Abschnitt 1.4 ist leer; PDF-Seite 38 enthält anstelle der Abhängigkeitsabbildung einen großen TODO-Platzhalter.

Die Arbeit sollte ihren Beitrag nicht als vollständige ASBAC- oder Reference-Monitor-Realisierung darstellen, sondern als **prototypische, auf `file_open` begrenzte Untersuchung eines kernelgestützten Policy-Enforcement-Pfads mit pollingbasierter best-effort Nachkontrolle bestehender Deskriptoren**. Diese präzisere Einordnung schwächt die Arbeit nicht; sie macht ihren Beitrag wissenschaftlich belastbar.

## 2. Gesamtbewertung

| Kriterium | Bewertung des aktuellen Stands | Begründung |
|---|---|---|
| Problemstellung | gut | Dynamische Entscheidungsgrundlagen und bestehende Dateiöffnungen ergeben ein plausibles Problem. Der konkrete Forschungsgap gegenüber ASBAC/SAPL, UCON und Linux-MAC fehlt noch. |
| Forschungsfrage | gut, aber zu breit | Klar formuliert, doch „ASBAC im Linux-Kernel“ überdeckt, dass wesentliche Nachkontrolle im Userspace stattfindet und nur `file_open` betrachtet wird. |
| Methodik | deutliche Schwäche | Es fehlt eine explizite Forschungsmethode bzw. ein nachvollziehbarer Erkenntnisweg von Literatur über Anforderungen und Design bis Evaluation. |
| Wissenschaftliche Argumentation | solide, überarbeitungsbedürftig | Viele Entscheidungen sind erklärt; zentrale Aussagen zu ASBAC, Reference Monitor, Eignung und Sicherheit sind noch nicht ausreichend belegt oder eingegrenzt. |
| Struktur | gut mit Redundanzen | Grundlagen, Anforderungen, Konzept und Umsetzung folgen logisch. Kapitel 4 und 5 wiederholen sich teilweise; Abschnitt 1.4 ist leer. |
| Technische Tiefe | sehr gut für Bachelor-Niveau | eBPF-LSM, feste ABI, Double Buffering, Tail Calls und `ptrace`-Enforcement sind anspruchsvoll und konkret. |
| Eigenleistung | hoch, aber noch nicht sauber abgegrenzt | Der Prototyp ist substanziell. Der neue wissenschaftliche bzw. technische Beitrag gegenüber SAPL/ASBAC, UCON und vorhandenen Linux-Lösungen muss explizit herausgearbeitet werden. |
| Nachvollziehbarkeit | gut im Design, offen im Nachweis | Codebeschreibung ist detailliert; reproduzierbare empirische Ergebnisse und Sicherheitsgrenzen fehlen noch. |

## 3. Bewertung pro Kapitel

### Kapitel 1 – Einleitung

**Bewertung: solide, aber überarbeitungsbedürftig.** Forschungsfrage und Ziel sind verständlich. Motivation, Forschungslücke, eigener Beitrag, Scope und Nicht-Ziele bleiben zu knapp. Die Aussage, LSM stelle Mechanismen „mittels ABAC“ bereit, ist sachlich zu eng: LSM ist ein Hook-Framework und nicht selbst ein ABAC-Mechanismus. Abschnitt 1.4 ist leer.

### Kapitel 2 – Grundlagen

**Bewertung: deutliche wissenschaftliche Schwächen bei ansonsten guter technischer Einführung.** Reference Monitor, ABAC, LSM, BPF, Maps und Aya werden verständlich eingeführt. Kritisch ist, dass die namensgebende ASBAC-Primärliteratur fehlt und ASBAC stattdessen über verwandte UCON-Literatur definiert wird. Ein eigenständiger Related-Work-Abschnitt fehlt. Die drei Reference-Monitor-Eigenschaften werden korrekt genannt, aber später nicht systematisch am Prototyp geprüft.

### Kapitel 3 – Anforderungsanalyse

**Bewertung: gut strukturiert, aber semantisch inkonsistent.** IDs und Akzeptanzkriterien schaffen gute Evaluierbarkeit. FA-07 ist mit „unmittelbar“ nicht durch den pollingbasierten Entwurf erfüllbar. FA-03 und FA-08 fehlen in der Nummerierung. Sicherheitsanforderungen, Threat Model und negative Akzeptanzkriterien sind zu schwach. OA-03 besitzt keinen messbaren Grenzwert.

### Kapitel 4 – Konzeption

**Bewertung: gut bis sehr gut technisch, wissenschaftlich überarbeitungsbedürftig.** Alternativen und Konsequenzen werden erfreulich oft diskutiert. Der Abschnitt ist jedoch lang und teilweise repetitiv. Die Wahl eBPF-LSM wird vor allem mit schnellerem Testen begründet; systematische Kriterien und ein Vergleich mit klassischem LSM, fanotify, seccomp bzw. reinem Userspace fehlen. Der Userspace-PEP wird konzeptionell zu stark als gezielter Entzug dargestellt. Trust Boundaries, TCB, Angreifermodell und Rechte an gepinnten Maps fehlen als zusammenhängende Analyse.

### Kapitel 5 – Entwurf und Umsetzung

**Bewertung: technisch stark, aber mit kritischen Nachweislücken.** Die Beschreibung entspricht dem Code überwiegend bemerkenswert genau. Positiv sind die expliziten Grenzen bei Polling, Generationen und `ptrace`. Kritisch bleiben UID-Semantik, FD-Reuse, Multi-Threading, `mmap`, Descriptor-Duplikation/-Vererbung, Map-Manipulation und der Ausfall des Userspace-PEP. PDF-Seite 38 ist formal nicht abgabefähig.

### Kapitel 6 – Evaluation

**Bewertung des vorgesehenen Ansatzes: gute Grundlage, noch nicht bewertbar.** Die vorhandene Struktur nennt Umgebung und E2E-Szenarien. Das Kapitel muss noch Messergebnisse, Wiederholungen, Rohdaten/Statistik, Baselines, Traceability und robuste Negativtests enthalten. Die aktuelle Unvollständigkeit wird gemäß Aufgabenstellung nicht als Mangel gewertet.

### Kapitel 7 – Zusammenfassung und Ausblick

**Bewertung: noch nicht bewertbar.** Der Platzhalter wird nicht negativ gewertet. Die erforderlichen Inhalte sind in [04_Evaluation_und_Ausblick.md](04_Evaluation_und_Ausblick.md) abgeleitet.

## 4. Vorläufiges Gutachten

Die Arbeit behandelt mit der prototypischen Durchsetzung dynamischer attributbasierter Zugriffsentscheidungen über eBPF-LSM ein anspruchsvolles Thema an der Schnittstelle von Betriebssystemen und IT-Sicherheit. Der entwickelte Rust-Prototyp weist eine erhebliche technische Eigenleistung auf. Besonders hervorzuheben sind die Aufteilung zwischen Userspace und Kernelspace, die feste Map-Repräsentation, die generationsbasierte Aktualisierung und die gemeinsame Policy-Auswertung in Kernel- und Userspace-Komponenten.

Der schriftliche Teil ist in weiten Teilen nachvollziehbar aufgebaut und technisch detailliert. Wesentliche wissenschaftliche Defizite bestehen derzeit jedoch bei der Einordnung des namensgebenden ASBAC-Konzepts, beim Stand der Forschung, bei der Übertragung der Reference-Monitor-Eigenschaften sowie bei der kritischen Absicherung der nachträglichen Durchsetzung. Der polling- und `ptrace`-basierte Userspace-PEP erfüllt die derzeit formulierte Forderung eines unmittelbaren und zuverlässigen Entzugs nur eingeschränkt. Diese Einschränkung muss nicht zwingend technisch vollständig gelöst werden, aber sie muss systematisch untersucht, evaluiert und als Prototypgrenze ausgewiesen werden.

Unter der Voraussetzung, dass die Related-Work-Lücke geschlossen, die Claims präzisiert, die Code-/Thesis-Inkonsistenzen behandelt und eine belastbare Evaluation ergänzt werden, besitzt die Arbeit gutes bis sehr gutes Potenzial.

## 5. Vorläufige Note

**Aktueller Stand: 2,7.** Die Note berücksichtigt die starke technische Substanz, aber auch die derzeit gravierende Related-Work-Lücke, fehlende empirische Nachweise, die unvollständige Reference-Monitor-/Security-Argumentation und formale TODOs. Kapitel 6 und 7 werden dabei nicht allein wegen ihres Platzhalterstatus abgewertet; bewertet wird, dass zentrale bestehende Claims aktuell noch ungetragen sind.

**Potenzial nach sinnvoller Überarbeitung und vollständiger Evaluation: 1,7.** Eine 1,3 erscheint erreichbar, wenn zusätzlich eine sehr saubere ASBAC-Abgrenzung, ein explizites Threat Model, reproduzierbare und statistisch angemessene Messungen sowie eine überzeugende Diskussion der Revocation-Grenzen geliefert werden. Eine 1,0 wäre nur bei außergewöhnlich stringenter wissenschaftlicher Einordnung und sehr belastbarer Evaluation realistisch.

## 6. Detailberichte

- [01_Probleme_nach_Prioritaet.md](01_Probleme_nach_Prioritaet.md) – vollständige Problemblätter mit Fundstelle, Begründung, Lösungen, Aufwand und Nutzen
- [02_Quellen_Audit.md](02_Quellen_Audit.md) – Quellenprüfung und fehlende Belege
- [03_Thesis_vs_Code.md](03_Thesis_vs_Code.md) – Architektur-, Security- und Implementierungsabgleich
- [04_Evaluation_und_Ausblick.md](04_Evaluation_und_Ausblick.md) – konkreter Plan für Kapitel 6 und 7
- [05_Priorisierte_ToDos.md](05_Priorisierte_ToDos.md) – umsetzbare Reihenfolge vor Abgabe

## 7. Prüfgrenzen

Die PDF wurde vollständig textuell und in gerenderten Seitenübersichten geprüft. Die zentralen öffentlich verfügbaren Primärquellen wurden stichprobenartig inhaltlich verifiziert. Nicht jede einzelne URL und nicht jede zitierte Passage konnte vollständig bis auf Satzebene geprüft werden; dies ist im Quellen-Audit ausdrücklich gekennzeichnet. Es wurden keine Quellen erfunden. Repository-Tests wurden nicht als Beweis ausgeführt, weil die Aufgabe eine Begutachtung und keine Veränderung bzw. Betriebsaufnahme des Systems verlangt; vorhandener Testcode und Skripte wurden als Implementierungsartefakte gelesen.

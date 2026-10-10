# Recherche zu Kapitel 2: bestehende Lösungen, verbleibende Frage und Eigenleistung

Stand: 5. Oktober 2026. Grundlage sind die Forschungsfrage in `sections/01-einleitung.tex`, Kapitel 2 sowie die Architektur und Grenzen in Kapitel 4 und 7. Dies ist eine gezielte Literatur- und Dokumentationsrecherche, kein systematisches Literaturreview. Aussagen über fehlende Funktionen beziehen sich auf die untersuchten Quellen; sie beweisen keine weltweite Abwesenheit entsprechender Lösungen. Die bestehenden Evaluationsergebnisse wurden hierfür nicht erneut ausgeführt.

## 1. Konkrete Problemstellung als Vergleichsmaßstab

Die Arbeit untersucht eine Kombination aus fünf Aufgaben:

1. Textuelle Policies in eine begrenzte, im eBPF-LSM-Pfad auswertbare Repräsentation überführen.
2. Externe veränderliche Attribute und Zeitinformationen aus dem Userspace für Dateiöffnungsentscheidungen bereitstellen.
3. Neue Dateiöffnungen unmittelbar über `file_open` zulassen oder verweigern.
4. Nach Policy- und Attributaktivierungen sowie an relevanten Zeitgrenzen bereits geöffnete Dateien erneut bewerten und selektiv einen FD-Schließversuch ausführen.
5. Machbarkeit, Aktualisierungsverhalten und Grenzen dieses Zusammenspiels untersuchen.

Beispiel: Eine Datei darf nur bei aktivem Freigabeattribut und innerhalb eines Zeitfensters geöffnet werden. Nach Wegfall der Freigabe werden neue Öffnungen verweigert. Zusätzlich sollen bereits bestehende FDs erkannt und gezielt behandelt werden, auch wenn der Prozess gerade keinen weiteren Dateisystemaufruf ausführt.

Dabei sind drei verschiedene Ergebnisse auseinanderzuhalten: eine neue Öffnung verweigern, eine spätere Lese-/Schreiboperation verweigern und einen FD aktiv schließen. Keines davon macht bereits gelesene Daten rückgängig; ein FD-Schluss beseitigt auch nicht automatisch bestehende Speicherabbildungen oder weitere Referenzen.

## 2. Was vorhandene Ansätze bereits lösen

| Ansatz | Bereits gelöster Teil | Bezug zur konkreten Arbeit und verbleibende Abgrenzung |
| --- | --- | --- |
| UCONABC, Park und Sandhu (2004) | Modelliert fortdauernde Kontrollen und veränderliche Attribute; integriert Autorisierungen, Verpflichtungen und Bedingungen. | Die Modellidee ist Vorwissen. Das Modell legt keine konkrete eBPF-LSM-Implementierung oder Linux-FD-Entzugsschnittstelle fest. |
| SAPL / ASBAC, Heutelbeck (2021), SAPL-Dokumentation 3.0.0 | Autorisierungs-Subscriptions, Einbeziehung von Datenströmen und aktualisierte PDP-Entscheidungen an einen PEP. | Die ereignisabhängige Neubewertung ist bereits gelöst. Die untersuchte Dokumentation beschreibt keinen fertigen eBPF-LSM-PEP mit selektivem Entzug fremder Linux-FDs. Der eigene Prototyp besitzt seinerseits keine individuellen Decision Streams. |
| Teigão, Maziero und Santin (2011) | Implementiert UCON-orientierte lokale Dateikontrolle im Betriebssystemkernel mit Policyparser, Attributen und laufenden Prüfungen. | Sehr nahe Vorarbeit: Die grundsätzliche Machbarkeit dynamischer Dateinutzungskontrolle im Kernel ist bereits gezeigt. Implementiert in OpenBSD 4.1 durch Kerneländerungen; laufende Prüfungen bei `read`/`write`, keine eBPF-LSM-Architektur. |
| SELinux, exemplarisch Linux v6.12 | `selinux_file_permission` prüft Änderungen an Subjekt-/Objektkennungen und Policysequenz und veranlasst gegebenenfalls eine erneute Berechtigungsprüfung. | Bereits geöffnete Dateien sind nicht generell von späteren Kontrollen ausgeschlossen. Diese Prüfung ist an eine vermittelte Operation gebunden; sie entspricht keinem ereignisgetriebenen Scan mit aktivem FD-Schluss. Eine externe Attributintegration wäre ein gesonderter Entwurf. |
| AppArmor | Beschränkt Anwendungen über Profile und pfadbasierte Dateiregeln; unterstützt Profilersetzung und Revalidierung bestehender Dateiobjekte. | Laut Profilverwaltungsdokumentation können bereits geöffnete Ressourcen nach einer Profilersetzung zugänglich bleiben. Revalidierung ist kein allgemeiner aktiver FD-Entzug. |
| KubeArmor, BPF-LSM-Enforcer | Übersetzt deklarative Regeln in BPF-Maps und setzt sie an LSM-Hooks durch; adressiert Datei-, Prozess- und Netzwerkzugriffe. | Policies im Userspace verwalten und über Maps im Kernel auswerten ist bereits Praxis. Die untersuchten Quellen belegen keine vollständige ASBAC-Subscription-Verarbeitung oder den hier untersuchten selektiven FD-Schließmechanismus. |
| Tetragon | Kernelbasierte Filter und Durchsetzung; dokumentiert Rückgabewert-Override und Signale sowie Dateizugriffskontrollen über `security_file_permission`. | Auch die Kontrolle weiterer Dateioperationen ist bestehende Technik. Ein Prozesssignal und ein selektiver FD-Schluss haben unterschiedliche Auswirkungen. Die Quellen zeigen nicht die konkrete Kombination aus externen Attributgenerationen, Zeitgrenzen und FD-Nachbewertung dieser Arbeit. |
| BPFence, Galletta (September 2026) | Laut Abstract zustandsbehaftete Policies mit formaler Semantik, zeitlichen Ereignisbeziehungen und Übersetzung in eBPF-Monitore. | Aktuelle verwandte Forschung: Zustandsbehaftete eBPF-Policies sind keine tragfähige allgemeine Neuheitsbehauptung. Der Abstract belegt keine ASBAC-Attributstreams oder selektive FD-Revocation; diese Einordnung ist vorläufig und ersetzt keine Volltextanalyse. |

Primärquellen und genaue Fundstellen:

- **Park / Sandhu:** [The UCONABC usage control model](https://doi.org/10.1145/984334.984339), ACM TISSEC 7(1), 128–174, 2004. Die Abstractbeschreibung belegt Kontinuität und Mutabilität. Für den Ursprung dieser Konzepte geeigneter als allein die bereits zitierte UseCON-Verifikationsarbeit von 2018.
- **SAPL:** [Introduction, Version 3.0.0](https://sapl.io/docs/3.0.0/1_1_Introduction/), insbesondere die Beschreibung der Subscription zwischen PEP und PDP und der erneut übermittelten Entscheidungen. Die Demo von 2021 ist im Repository bereits als `heutelbeck2021asbac` enthalten, DOI 10.1145/3450569.3464397; der Verlagsvolltext war in dieser Recherche nicht abrufbar. Die Architektur wurde anhand der offiziellen Dokumentation geprüft.
- **Teigão et al.:** [Applying a usage control model in an operating system kernel – Autorenkopie](https://secplab.ppgia.pucpr.br/files/papers/2011-3.pdf), Journal of Network and Computer Applications 34(4), 1342–1352, DOI 10.1016/j.jnca.2011.03.019. Abschnitte 7.1–7.3, S. 1349–1350: Prüfungen bei Öffnen, Lesen, Schreiben und Schließen; OpenBSD 4.1; verweigerte weitere Nutzung bei veränderten Bedingungen. Schon die Objektidentifikation mittels Device/Inode ist dort beschrieben.
- **SELinux:** [Linux v6.12, security/selinux/hooks.c](https://github.com/torvalds/linux/blob/v6.12/security/selinux/hooks.c), `selinux_file_permission`, insbesondere Vergleich von `fsec->pseqno` mit `avc_policy_seqno()` und Aufruf von `selinux_revalidate_file_permission`. Dieser konkrete Versionsstand vermeidet eine unbestimmte Behauptung über alle SELinux-Versionen.
- **KubeArmor:** [Runtime Enforcer](https://docs.kubearmor.io/kubearmor/quick-links/kubearmor_overview/runtime_enforcer) und [BPF](https://docs.kubearmor.io/kubearmor/quick-links/kubearmor_overview/bpf). Die Dokumentation beschreibt Policyübersetzung, BPF-Maps und unmittelbare Entscheidungen an LSM-Hooks.
- **Tetragon:** [Enforcement](https://tetragon.io/docs/concepts/enforcement/), [Filename access](https://tetragon.io/docs/use-cases/filename-access/) und [Policy Enforcement](https://tetragon.io/docs/getting-started/enforcement/). Die Quellen unterscheiden Operationsverweigerung und Prozesssignale; die Dateizugriffsdokumentation behandelt `security_file_permission`.
- **BPFence:** [Enforcement of In-Kernel Stateful Security Policies via eBPF](https://arxiv.org/abs/2609.13930), arXiv v1 vom 12. September 2026. Hier nur Abstract und bibliografische Angaben ausgewertet. Falls der Literaturstichtag der Thesis davor liegt, als spätere Entwicklung kennzeichnen.

## 3. Welche Lücke sich daraus tatsächlich ableiten lässt

Eine allgemeine Lücke »dynamische Zugriffskontrolle beziehungsweise fortdauernde Autorisierung fehlt unter Betriebssystemen« ist durch die Vorarbeiten widerlegt. Ebenso wäre »Policies aus dem Userspace werden erstmals über BPF-Maps im Kernel durchgesetzt« gegenüber KubeArmor nicht haltbar.

Die belastbare verbleibende Frage ist eine **konkrete Integrations- und Untersuchungsfrage**: Wie lassen sich ausgewählte ASBAC-Eigenschaften mit begrenzten eBPF-LSM-Programmen für neue Dateiöffnungen verbinden, während bestehende Nutzungssituationen ereignisabhängig im Userspace rekonstruiert und selektiv behandelt werden? Welche Garantien und Grenzen entstehen an dieser Schnittstelle?

In den untersuchten Quellen ist diese genaue Kombination nicht nachgewiesen. Das rechtfertigt die Untersuchung, aber keine Behauptung, der Prototyp sei weltweit die erste Lösung. Die Wahl des aktiven FD-Schlusses ist außerdem eine Entwurfsentscheidung: Sie ist keine notwendige Voraussetzung fortdauernder Autorisierung. Ein zusätzlicher Kernelhook kann spätere Operationen erneut prüfen und verweigern, ohne den FD zu schließen.

Der eigene Prototyp schließt die allgemeine Revocation-Lücke selbst nicht vollständig. Er kontrolliert nur neue Öffnungen im Kernel und ergänzt einen Best-Effort-Schließversuch. FD-Wiederverwendung, weitere Referenzen, Speicherabbildungen, laufende E/A und nicht erreichbare Prozesse begrenzen dessen Aussagekraft. Das ist ein Untersuchungsergebnis und gehört zur Beitragsbeschreibung.

## 4. Worin die Eigenleistung besteht

Auf Basis der Architektur- und Ergebnisbeschreibung der Thesis besteht die Eigenleistung in:

1. **Entwurf und Implementierung der Übertragung:** begrenzte eigene Policyrepräsentation, dynamische Attribute und Zeitinformationen für den eBPF-LSM-Entscheidungspfad.
2. **Koordination veränderlicher Zustände:** Vorbereitung und Aktivierung von Policy-/Attributständen sowie definierte Auslöser für die Nachbewertung. Das Zwei-Bank-Verfahren ist eine Implementierungsleistung; daraus folgt allein keine Garantie einer unveränderten Lesesicht über mehrere schnelle Generationenwechsel.
3. **Verbindung beider Entscheidungspfade:** unmittelbare Öffnungskontrolle und lokale Nachbewertung bestehender FDs mit gemeinsamer Policysemantik, Objektidentifikation und festgelegter Real-UID-Semantik.
4. **Selektiver Entzugsprototyp:** Rekonstruktion über `/proc` und gezielter `ptrace`-gestützter Schließversuch im Zielprozess einschließlich Fehlerbehandlung.
5. **Empirische Untersuchung:** Funktionsnachweise und Latenzmessungen auf dem dokumentierten Linux-Zielsystem sowie Analyse technischer Grenzen. Die Ergebnisse belegen keine Überlegenheit gegenüber SAPL, SELinux, KubeArmor oder Tetragon, da kein entsprechender Vergleich durchgeführt wurde.

Diese Punkte begründen einen eigenen technischen und empirischen Beitrag. ASBAC, UCON, LSM, eBPF, Maps, Device/Inode-Identifikation und Double Buffering sind dabei verwendete Grundlagen und keine neu erfundenen Konzepte.

## 5. Formulierungsvorschlag für Kapitel 2

> Fortdauernde Autorisierung und veränderliche Entscheidungsgrundlagen sind bereits durch Usage-Control-Modelle und ASBAC beschrieben. SAPL realisiert hierfür eine Publish-Subscribe-Architektur mit aktualisierten Autorisierungsentscheidungen. Auch die Betriebssystemdurchsetzung ist Gegenstand bestehender Arbeiten: Teigão et al. implementieren UCON-orientierte Prüfungen lokaler Dateizugriffe im OpenBSD-Kernel. SELinux kann Berechtigungen bereits geöffneter Dateien bei relevanten Zustandsänderungen erneut prüfen. KubeArmor und Tetragon zeigen zudem die praktische Durchsetzung deklarativer Sicherheitsregeln mithilfe von Linux-Kernelmechanismen und eBPF.
>
> Die vorliegende Arbeit untersucht vor diesem Hintergrund die Übertragung ausgewählter ASBAC-Eigenschaften auf einen begrenzten eBPF-LSM-Prototyp für Linux-Dateiöffnungen. Ihr Beitrag umfasst die Bereitstellung dynamischer Entscheidungsgrundlagen, die Abstimmung von Kernel- und Userspace-Auswertung sowie die ereignisabhängige Nachbewertung bestehender File Descriptors mit einem selektiven Schließversuch. Dabei wird insbesondere untersucht, welche Einschränkungen aus der Rekonstruktion bestehender Zugriffe und dem nachträglichen Eingriff in den Zielprozess entstehen. Der Prototyp übernimmt keine vollständige ASBAC-Subscription-Architektur und gewährleistet keinen vollständigen oder atomaren Entzug sämtlicher Nutzungsformen.

Der erste Absatz benötigt die oben genannten Literaturbelege. Der zweite beschreibt die eigene Arbeit und sollte auf Konzeption und Evaluation verweisen.

## 6. Konkrete Konsequenzen für Kapitel 2

- Einen Abschnitt **»Verwandte Arbeiten und Abgrenzung des eigenen Ansatzes«** ergänzen. Kapitel 1 kündigt eine solche Abgrenzung bereits an; Kapitel 2 enthält bislang vor allem Grundlagen und die Abgrenzung zu SAPL.
- UCON am Originalmodell von Park und Sandhu verankern; Gouglidis et al. weiterhin für UseCON beziehungsweise formale Verifikation verwenden.
- Teigão et al. als wichtigste fachlich nahe Kernelvorarbeit aufnehmen; OpenBSD und die operationsgebundene laufende Prüfung ausdrücklich nennen.
- SELinux, AppArmor sowie KubeArmor/Tetragon als technische Vergleichsansätze behandeln. Die Abgrenzung wurde inzwischen in Kapitel 2 aufgenommen.
- Die Aussage zu `file_open` ausdrücklich auf **diesen Hook** begrenzen: Eine spätere Nutzung durchläuft `file_open` nicht erneut; Linux bietet aber weitere Kontrollpunkte. Daraus folgt keine generelle Unfähigkeit von LSM zur fortdauernden Kontrolle.
- Grundlagen und eigenen Entwurf stärker trennen: Policygenerationen, die genaue Rollenverteilung und der gewählte Entzugsmechanismus gehören in ihrer konkreten Ausgestaltung zu Kapitel 4. Kapitel 2 erläutert die Voraussetzungen und stellt alternative Lösungen gegenüber.

Für eine stärkere Neuheitsaussage wären zusätzlich eine dokumentierte systematische Suche, Volltextvergleiche weiterer UCON-/SELinux-Integrationen und ein Vergleich mit konkreten Versionen der Laufzeitschutzsysteme nötig. Für den hier formulierten Machbarkeits- und Untersuchungsbeitrag ist eine solche Erstmaligkeitsbehauptung nicht erforderlich.

## 7. Ergänzung zu AppArmor

AppArmor ist ein Linux-Sicherheitsmodul zur Beschränkung von Anwendungen, kein eigenes Streaming-Autorisierungsmodell. Profile formulieren unter anderem erlaubte Dateipfade und Operationen. KubeArmor kann solche Profile als Durchsetzungsbackend verwenden; der BPF-LSM-Enforcer ist eine alternative technische Umsetzung innerhalb von KubeArmor.

Die [offizielle Profilverwaltungsdokumentation](https://apparmor-documentation-c38b15.gitlab.io/documentation/getting-started/managing-profiles/) beschreibt, dass neue Entscheidungen nach einer Profilersetzung das neue Profil verwenden, bereits geöffnete Ressourcen aber zugänglich bleiben können. Im [Kernelcode von Linux v6.12](https://github.com/torvalds/linux/blob/v6.12/security/apparmor/file.c) enthält `aa_file_perm` zwischengespeicherte Berechtigungen und eine bedingte Revalidierung. Daher weder »AppArmor kontrolliert ausschließlich open« noch »ein Reload entzieht zuverlässig alle bestehenden Zugriffe« behaupten. Eine Prüfung weiterer Operationen schließt außerdem keinen FD aktiv. Die Einordnung beruht auf Dokumentation und Quellcode, nicht auf einem Laufzeittest mit dem Zielkernel.

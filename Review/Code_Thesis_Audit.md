# Thesis-vs.-Code-Audit

Stand: 11.09.2026. Gegenstand ist der aktuelle Arbeitsbaum bei HEAD `756af74`, einschließlich der vor Beginn vorhandenen Änderungen. Die Analyse ist statisch; auf diesem macOS-System wurden weder `test.sh` noch privilegierte Linux-Tests ausgeführt. Historische Läufe werden als archivierte Evidenz, nicht als selbst wiederholte Tests bewertet.

## 1. Umfang und Vorgehen

Nach der vollständigen Lektüre aller sieben Thesis-Kapitel wurden die acht Crates anhand der beschriebenen Architektur geprüft: Hook-Einstieg, sämtliche aktiven eBPF-Auswertungsstufen, Maps und Hilfszugriffe, gemeinsame Datei-/Attributsemantik, Loader und Commitpfade, Runtime-Lebenszyklus, Userspace-PEP und vollständiger FD-Revoker sowie Administrations-/Build-Schnittstellen. Tests wurden entlang der Aussagen ausgewählt, insbesondere Generationen, Kapazitäten, Trigger, UID, FD-Entzug und Performance. Generierte Kerneltypen wurden nicht vollständig begutachtet; ein vollständiges Security-Audit aller Betriebssystempfade ist nicht Gegenstand dieser Bewertung.

Die Produktionsdateien der relevanten Crates unterscheiden sich gegenüber `35e1d2b` im geprüften Vergleich nur durch die Umordnung von Hilfsfunktionen vor das Testmodul in `tails-pdp-userspace-common/src/lib.rs`. Die Test-/Runnerdateien und Thesis haben zusätzliche Änderungen. Das beseitigt die konkret berichtete Clippy-Strukturursache, belegt jedoch keinen neuen Gesamttesterfolg.

## 2. Gegenüberstellung

Dateien in der Tabelle sind relativ zum Repository angegeben; Funktionsnamen und Zeilen beziehen sich auf den begutachteten Stand.

| Thema | Aussage Thesis | Tatsächliche Implementierung | Konsistent? | Relevanz / Lösung |
|---|---|---|---|---|
| Acht Crates | §5.1 trennt Kernel, Loader, PEP, gemeinsame Typen, Diagnose | Workspace/Cargo-Manifeste entsprechen der Aufteilung | Ja | Gute Modularität; echte Abbildung fehlt (F01) |
| Abhängigkeiten | Hauptprogramm bindet Loader/PEP/common ein; eBPF als Build-Abhängigkeit | `tails-pdp/Cargo.toml:9,29`, `build.rs:17` | Ja | Abhängigkeitsliste aus Manifesten in Grafik überführen |
| Aktiver Hook | Nur file_open | `ebpf/src/hooks.rs:7`; Hauptprogramm hängt nur attach-markierten Einstieg an | Ja | Kein Anspruch auf vollständige Dateinutzung |
| Vorgängerentscheidung | Frühere BPF-LSM-Ablehnung erhalten | `hooks.rs:10`: ctx.arg(1), unveränderte Rückgabe bei !=0 | Ja | Schutzverkettung richtig behandelt |
| Real UID | Explizit Real UID | ctx.uid(); Aya b93ee8c ruft Helper und castet unteren Teil; /proc erstes Uid-Feld | Ja im definierten Modell | Keine EUID-/FSUID-/Namespace-Allgemeingarantie |
| Kommando | Kommando aus Kontext und Prozessstatus | Kernel task comm; Userspace Name des /proc/PID/status | Teilweise | Thread-/Namensgrenzen unten beachten |
| Ressourcen | Device/Inode statt Pfadvergleich | `helpers.rs:17`, resolve_resource_identity, encode_kernel_dev_t, stat auf /proc-FD | Ja im Zielscope | Dateiobjekt, nicht Dateiinhalt; Ersetzen erfordert erneutes Laden |
| Policy-Filter | Wildcards bei nicht belegten Filtern | `common/src/lib.rs:811,815,819` | Ja | Empty command/Nullidentität sind Wildcards |
| Combining | Deny hat Vorrang, sonst Allow | `DecisionState::lsm_return_value:776` | Ja | Permit-only schränkt nichts ein; F13 |
| Stream-Konjunktion | Alle Attribute müssen passen | Begrenzte Schleife in beiden PEPs, gemeinsame Vergleichsfunktion | Ja | E2E-12 und Komponentenprüfung stützen Semantik |
| Fehlende Attribute | Policy nicht erfüllt | ATTRIBUTES.get None beziehungsweise Userspace get.ok → false | Ja | Pauschales „fehlende Map-Werte fail-closed“ präzisieren |
| Zeit | CURRENT_TIME und gemeinsame UTC-Umrechnung | `PolicyTime::from_unix_seconds:256`, time.rs | Ja | PEP schreibt bei Zeittrigger zusätzlich selbst CURRENT_TIME; nicht nur Loader ist Schreiber |
| Zeitaktualisierung | Einmal pro Sekunde, getrennt vom Scan | Tokio-Intervall; blockierende Scans unterbrechen das Polling | Eingeschränkt | F05; keine sekündliche Frischegarantie |
| Tail Calls | Einstieg → statisch → Stream → Combining | ProgramArray mit Indizes 0/1/2, drei Folgestufen | Ja | Fehlender Tail Call verweigert |
| Temporäre Entscheidungen | Per-CPU, nicht gepinnt | `maps.rs:22`, drei u32-Slots | Ja | Keine Decision-Stream-Kommunikation mit Userspace |
| Policygeneration | Erst Zielbank vollständig schreiben, dann umschalten | `commit_policy_generation:243` | Ja als Publikationsreihenfolge | Keine unbedingte Leser-Snapshot-Garantie; F04 |
| Attributgeneration | Inaktive Bank leeren, schreiben, aktivieren | `commit_attributes:481` | Ja | Beide Generationen unabhängig, kein gemeinsamer Policy-/Attribut-Commit |
| Attributkapazität | Insgesamt 1024 Map-Einträge | retained + requested <= capacity vor jeder Mutation | Ja | 512 ist kein pauschales Per-Bank-Limit: 600 alte + 424 neue können passen; 600+600 nicht |
| Validierung | Format, Namen, vier Bedingungen, Policykapazität | Parser und translate/ensure-Funktionen | Weitgehend ja | Kein Voll-SAPL, keine allgemeine Policy-Engine |
| Ungültige Updates | Vorherige Generation bleibt | Parser-/Commitfehler werden behandelt | Ja für behandelte Fälle | Policy-Dateilesefehler propagieren fatal; F06 |
| Policy-Retry | Unveränderte Fehlstände werden nicht erneut verarbeitet | `documents_need_sync:259` berücksichtigt last_failed | Ja | Auch transient gescheiterte Commits werden bei identischem Inhalt nicht automatisch wiederholt |
| Startreihenfolge | Initiale Zustände vor Hook-Attach | `main.rs:104–127` | Ja | Leerer Policybestand ist trotzdem gültig und erlaubt; „nicht mit leerer Konfiguration“ zu absolut |
| Beobachtung | Rekursives inotify, 100 ms Bündelung | `fs_watch.rs`, beide run-Schleifen | Ja | Kein Ruhezeit-Debounce nach letztem Event; F09 |
| Trigger | Nur erfolgreiche Aktivierung bzw. Zeitgrenze | Kanalgröße 1, try_send, Timer | Ja | Keine individuele Subscription, kein garantierter Bericht jeder Zwischengeneration |
| Parallelität | Während Scan laufen Loader weiter | Direktes select!, synchroner run_scan | Nein | F05 |
| Scan-Zustand | Generation/Zeit einmal auswählen | `read_scan_context:256` | Ja als Auswahlwerte | Keine Kopie aller Policy-/Attributwerte; interne Updates während Scan aktuell blockiert |
| FD-Erfassung | Nur reguläre Dateien unter /proc | `read_process_fds:570`, `read_file_identity:611` | Ja | Ausgeblendete/unlesbare Prozesse übersprungen; globale /proc-Lesefehler können wie leere Menge wirken |
| Selektiver Close | PID/FD-deduplizierter Versuch | `enforce_violation:534` | Ja als Versuch | Keine erneute Identitätsprüfung unmittelbar vor Close; bekannte Race-Grenze |
| ptrace | Register sichern, Text patchen, close, restaurieren | `fd_revoker.rs:39–95` | Ja, aber unvollständig bewertet | F14; Stop-/Signal-/Thread-/Cleanup-Risiken |
| Ausfall Userspace | Fehler beendet Prozess | main select! mit ?; Aya-Link nicht gepinnt | Ja, Konsequenz fehlt | Der eigene Hook entfällt; Maps allein erhalten den Schutz nicht (F06) |
| Map-ABI-Prüfung | Größen und maximale Eintragszahl | `policy_loader.rs:15` | Ja | Keine semantische ABI-Versionskennung, keine vollständige Schemaprüfung |
| Administration | Nur Öffnen/Lesen/Iterieren | `admintool/src/maps.rs`, lib.rs und output.rs | Ja | Diagnoseansicht ist kein atomarer Snapshot und kein individueller Audittrail |
| Debuglogging | Optional und standardmäßig aus | DEBUG_LOGGING und env_flag_enabled | Ja | Keine reguläre Decision-Stream-Übertragung |
| Build | eBPF-Artefakt eingebettet | aya_build + include_bytes_aligned | Ja | Erfolgreicher Build ersetzt keinen Verifierlauf |
| Clippy | Noch bestehender items_after_test_module-Befund | Aktuelle Deklarationen stehen bereits vor Tests | Nur historisch | F08; keine unnötige erneute Codekorrektur empfehlen |

## 3. Sicherheitsbewertung

### Trust Boundaries und TCB

Die tatsächliche Vertrauensbasis umfasst Kernel/BPF/LSM, Loader und Policyübersetzung, Attribute samt Quellen, CURRENT_TIME, gepinnte Maps, Runtime-Steuerung und Revoker. Die Sicherheit ist somit nicht auf das kleine eBPF-Programm reduzierbar. Gegen einen Administrator, der BPF-Programme oder Maps verändern oder die Runtime beenden kann, ist kein Schutz nachgewiesen. Die Runtime erzwingt keine eigene restriktive Rechtepolitik für alle Eingabeverzeichnisse und keine Ein-Instanz-Sperre. Dass Tests parallele Instanzen verhindern, ist keine entsprechende Eigenschaft des Produktionsprogramms.

Für die Bachelorarbeit genügt ein klarer Ausschluss dieses Angreifers plus dokumentierte Betriebsannahmen. Eine vollständige Capabilities-Minimierung oder Signaturinfrastruktur ist keine zwingende Voraussetzung des Machbarkeitsnachweises. Aktuelle Rechte an Pins und Quellen des entfernten Zielsystems wurden hier nicht überprüft und werden nicht behauptet.

### Fail-open und Fail-closed

| Zustand | Verhalten dieses Prototyps | Wissenschaftliche Einordnung |
|---|---|---|
| Keine passende Deny-Policy | Allow | Fachliche Standardentscheidung |
| Benötigtes dynamisches Attribut fehlt/Typ passt nicht | betreffende Policy nicht anwendbar; ohne anderes Deny Allow | Kein allgemeines Fail-safe-default-Modell |
| Hook-Kontext-/Generations-/Tail-Call-/Decision-State-Fehler | Ablehnung in den expliziten Fehlerpfaden | Lokales technisches Fail-closed |
| Ungültiger Policytext / fehlgeschlagener behandelter Commit | Letzte aktive Generation | Bewusstes Weiterarbeiten mit altem Zustand |
| Fehler beim Lesen der Policy-Dokumente oder fataler Watcherfehler | Runtime kann enden | Zusätzliches LSM-Enforcement entfällt mit dem Link |
| Blockierendes ptrace-Warten | Updater und weitere Scans warten mit | Veraltete dynamische Entscheidungsgrundlage möglich |
| Fehlgeschlagener FD-Entzug | Warnung; verbleibende Verstöße weiter versuchen | Best effort, kein garantierter Widerruf |

### Reference-Monitor-Kriterien

- **Always invoked / complete mediation:** für den angebundenen file_open-Pfad eine nachvollziehbare lokale Vermittlung; nicht für sämtliche Dateioperationen, FD-Übernahmen oder mmap-Nutzung. Die Thesis räumt den fehlenden vollständigen Reference Monitor korrekt ein.
- **Tamper proof:** hängt von vertrauenswürdigem Administrator, Kernel, Eingabequellen und Map-/Programmrechten ab. BPF-Verifikation schützt nicht gegen manipulierte fachliche Policywerte oder beendete Runtime. Diese Annahmen gehören in den Ist-Zustand, nicht allein in den Ausblick (F06).
- **Small enough for analysis/testing:** begrenzte Schleifen und geteilte Entscheidungslogik unterstützen Analysierbarkeit. 59 Tests und Verifier-Akzeptanz sind wertvolle Evidenz, kein Vollständigkeits-/Policykorrektheitsbeweis. Die Gesamt-TCB einschließlich Parser und ptrace ist erheblich größer als das Hookprogramm.

### Alternative Zugriffspfade und Ereignislücken

Die offen behandelten Grenzen dup/fork/mmap/FD-Reuse sind echte Grenzen, aber keine neu entdeckten verschwiegenen Fehler. Ergänzend gilt: Der Prototyp löst nicht für jede Änderung von comm, Real UID, Prozess-/FD-Lebenszyklus oder FD-Übertragung eine Nachbewertung aus. Eine Änderung während unveränderter Policy-/Attributlage kann bis zum nächsten relevanten Trigger unbehandelt bleiben. Das folgt aus der Triggerauswahl; ein konkreter Bypass wurde hier nicht ausgeführt. In der Thesis sollte die Menge überwachten Änderungen explizit begrenzt werden.

## 4. Ergänzende konkrete Befunde

### C01 – Kommando-Längen- und Identitätsgrenze (P2)

**Fundstelle:** §5.4.3, S.45; `policy_source.rs:694`, `common/src/lib.rs:266,815`; ctx.command() im Kernel; /proc-Parser `pep.rs:633`.

**Kategorie:** technische Korrektheit/Policysemantik. **Problem:** 16 Inhaltsbytes werden akzeptiert und exakt gespeichert. Linux comm ist jedoch ein 16-Byte-Feld einschließlich Nullabschluss; ein voller 16-Byte-Policyname kann deshalb regulär nicht identisch matchen. Der Taskname ist zudem kein manipulationsgeschützter Executable-Identifier, und der Userspace-Pfad liest den Gruppenleader statt jede Task.

**Warum/Auswirkungen:** Eine syntaktisch akzeptierte Deny-Policy kann wirkungslos bleiben. Die Aussage identischer Anfrageidentitäten ist nur im begrenzten Prozessmodell richtig. Quelle für comm: [proc_pid_comm(5)](https://man7.org/linux/man-pages/man5/proc_pid_comm.5.html); vor endgültiger Codekorrektur Zielkernelverhalten gegenprüfen.

**Lösung A:** Grenze auf 15 Inhaltsbytes beziehungsweise explizit normalisierte Kernel-comm-Semantik festlegen, ein 15-/16-Byte-Grenztest und Erklärung der Änderbarkeit. **Lösung B:** Kommando-Filter als demonstrativen, nicht sicherheitsstabilen Selektor markieren und überlange Namen als nicht sinnvoll nutzbar dokumentieren. **Empfehlung:** A, falls Codekorrekturen nach dem Review erfolgen; sonst B. **Aufwand:** mittel. **Nutzen:** mittel. **Benotung:** mittel, weil es fachliche Policywirkung betrifft.

### C02 – Keine automatische Wiederholung jedes erfolglosen Entzugs (P2)

**Fundstelle:** `pep.rs:107–136,534`, §5.7.2, S.52. **Kategorie:** Robustheit. **Problem:** Fehler werden protokolliert, dann wird auf ein neues Aktivierungs-/Zeitereignis gewartet. Bei zeitunabhängigen unveränderten Policies kann der nächste Scan ausbleiben; „nächster Scan“ ist keine zugesicherte Wiederholung. **Warum/Auswirkung:** Ein vorübergehend nicht erreichbarer FD bleibt eventuell dauerhaft unbehandelt, obwohl der Attach-Konflikt später verschwindet.

**Lösung A:** Fehler-/Retrysemantik explizit als „erneut nur bei neuem Trigger“ beschreiben. **Lösung B:** Begrenzte, identitätsgeprüfte Retries mit Backoff implementieren und auf dem Zielsystem testen. **Empfehlung:** A vor Abgabe, B Future Work. **Aufwand:** gering für A, hoch für B. **Nutzen:** mittel. **Benotung:** mittel; begrenzt FA-06 zusätzlich, ohne einen allgemeinen zuverlässigen Revoker zu verlangen.

## 5. Qualität der Implementierung im Bachelor-Kontext

**Positiv:** klare Zuständigkeiten; wiederverwendete semantische Funktionen; bewusste feste ABI mit C-Repräsentation/Padding; kontrollierte Aktivierung; brauchbare Kontextfehler; keine unkontrollierte Erweiterung auf weitere Hooks; reale Fehler-/Grenztests. Die Implementierung ist substantiell und deutlich mehr als ein minimales eBPF-Beispiel.

**Wissenschaftlich relevant:** F04/F05/F06/F14 und C01/C02 betreffen tatsächlich behauptete Eigenschaften. Sie wiegen höher als Stilfragen. Die Mischung von asynchroner Steuerung und blockierendem ptrace ist die wichtigste Robustheitsschwäche. Eine belastbare ptrace-Lösung wäre erheblicher Zusatzaufwand; für diese Arbeit ist eine offene Begrenzung angemessen.

**Überwiegend Wartbarkeit:** große Policyparser-Datei, verbliebene SocketBind-Strukturen ohne aktiven Hook, redundante Device-Konvertierung und ein Diagnosewörterbuch mit eigener vereinfachter Textanalyse. Diese Punkte rechtfertigen kein umfangreiches Refactoring kurz vor Abgabe. Die sicherheitsrelevante Semantik bleibt weitgehend nachvollziehbar.

## 6. Evidenz und Grenzen des Audits

Verifiziert wurden statische Pfade und archivierte Resultate. Nicht verifiziert wurden neue Kernel-/ptrace-Ausführungen, tatsächliche Rechte der entfernten VM, Vollständigkeit aller LSM-Aufrufpfade, formale Race-Freiheit und beliebige Signal-/Mehrthreadfälle. Aussagen über mögliche Interleavings sind ausdrücklich technische Analysen und keine erfundenen beobachteten Exploits. Der vorhandene RACE-01-Erfolg bleibt als begrenzte positive Beobachtung gültig.


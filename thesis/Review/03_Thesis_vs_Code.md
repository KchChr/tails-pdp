# Thesis-vs.-Code- und Security-Audit

## 1. Abgleich

| Thema | Aussage in Thesis | tatsächliche Implementierung | konsistent? | Handlungsbedarf |
|---|---|---|---:|---|
| Aktiver Hook | nur `file_open` | `#[lsm(hook = "file_open")]` mit Tail-Call-Kette | ja | Scope im Titel/Abstract klar halten |
| Kernel-PEP | unmittelbare Entscheidung bei neuer Öffnung | früher LSM-Rückgabewert wird erhalten; Tail-Call-Fehler führt zu `LSM_DENY` | ja | E2E auf Zielkernel nachweisen |
| Combining | deny-overrides, sonst allow | `DecisionState::lsm_return_value()`/Combine-Pfad; Permit ist für Endentscheidung nicht erforderlich | ja | Default-Permit explizit als Policysemantik diskutieren |
| Policy-Generationen | zwei Bänke, Aktivierung nach vollständigem Schreiben | `next_generation`, inaktive Bank, dann Generation setzen | grundsätzlich | Mehrfachupdates während langer Scans/Races evaluieren |
| Attributgenerationen | gleiche Double-Buffer-Idee | HashMap-Bank wird gelöscht/befüllt, dann aktiviert | grundsätzlich | Verhalten bei Fehlern und schneller Wiederverwendung testen |
| Zeit | einmal pro Sekunde, UTC-Konvertierung gemeinsam | gemeinsame `PolicyTime`, Map-Update | ja | Zeitauflösung, Clock-Sprünge und Aktualisiererausfall messen |
| Userspace-PEP Scan | ereignisbasierte Nachbewertung | erfolgreiche Policy-/Attributaktivierung oder relevante Zeitgrenze löst Scan aus; Fehler werden geloggt | ja | Aktivierungs- und Entzugslatenz messen |
| Zielgenauer Entzug | betroffener FD wird geschlossen, andere bleiben | `PTRACE_ATTACH`, Opcode-Patch, `close(fd)`, Register-/Text-Restore | nur im einfachen Fall | FD-Reuse, Threads, Signale, attach failures, EBADF testen/diskutieren |
| Geschützte Prozesse | allgemeine bestehende Zugriffe | PID 0, PID 1 und eigener PID werden nie behandelt | nein/Scope-Lücke | explizit als Ausschluss nennen und begründen |
| UID | Real UID als definierte Subjektidentität | Kernel `ctx.uid()` und erstes `/proc/status Uid`-Feld liefern Real UID; Userspace-Auswahl ist unit-getestet | ja für definierte Semantik | privilegierten E2E-Vergleich durchführen; Credential-Grenzen beibehalten |
| Command | Prozesskommando als Filter | Kernel `ctx.command()` vs. Userspace `/proc/status Name` | wahrscheinlich, aber nicht nachgewiesen | Trunkierung/Threadnamen und `comm`-Semantik testen |
| Ressource | Device/Inode in beiden Pfaden | Kernel liest File/Inode; Userspace `metadata(/proc/pid/fd/N)` und eigene `dev_t`-Kodierung | plausibel | Overlay-/Namespace-/Device-Kodierung auf Zielsystem testen |
| Fehlendes Attribut | keine klare globale Semantik | Bedingung matcht nicht; Deny greift nicht; Default-Permit | teilweise | explizite Policysemantik und Negativtest |
| Scanfehler | „weniger invasiv“, nächster Scan | Fehler lässt alle bestehenden Zugriffe weiterlaufen | ja, aber security-relevant | als fail-open für diesen Pfad benennen |
| Map-Manipulation | konsistente, gepinnte Zustände | jeder ausreichend privilegierte Map-Schreiber kann Zustand verändern | unvollständig beschrieben | Rechte/Capabilities/Threat Model |
| Read-only Admin | schreibt nicht in Maps | Codepfad laut Struktur lesend | ja | OS-Rechte dennoch dokumentieren |
| Weitere Aktionen | Arbeit beschränkt sich auf Dateiöffnung | Common-Crate enthält auch Socket-Bind-Strukturen, aktive eBPF-Maps/Hooks aber nur für Dateiöffnung | kein Laufzeitwiderspruch | als nicht aktiver/Legacy-/Erweiterungscode einordnen oder aus Beitrag ausklammern |

## 2. Security-Bewertung

### Neue Dateiöffnungen

Der Kernelpfad ist der stärkste Teil des Designs. Die Aufrechterhaltung einer früheren LSM-Ablehnung und das fail-closed Verhalten bei fehlgeschlagenen Tail Calls sind positiv. Die tatsächliche vollständige Abdeckung gilt jedoch nur für den konkret gewählten Hook und die dort modellierte Operation. `file_open` ist kein Beweis dafür, dass jede Form fortdauernder Nutzung oder jede Ressourcenzugriffsart vermittelt wird.

### Bestehende Zugriffe

Der Userspace-PEP ist eine **best-effort Kompensationskomponente**, kein gleichwertiger Reference Monitor:

- Er erkennt Änderungen frühestens beim nächsten Scan und benötigt zusätzliche Zeit für vollständiges `/proc`-Traversieren.
- `/proc` liefert keine atomare Momentaufnahme.
- Zwischen Identifikation und Entzug können PID/FD-/Dateizustände wechseln.
- `ptrace` adressiert einzelne Threads; andere Threads laufen weiter und teilen typischerweise die FD-Tabelle.
- `dup`, `dup2`, `fork`/Vererbung und SCM-Rechteübertragung können weitere Referenzen erzeugen.
- Ein `mmap` bleibt nach `close(fd)` grundsätzlich nutzbar; das Schließen ist nicht gleichbedeutend mit Entzug bereits etablierter Speicherabbildungen.
- PID 1, der PEP selbst und nicht attachbare Prozesse werden nicht entzogen.
- Ein Prozess kann vor dem Scan relevante Daten bereits gelesen oder kopiert haben; Revocation kann Vertraulichkeitsverlust nicht rückgängig machen.

### TOCTTOU beim FD-Entzug

Die Identität wird über `/proc/<pid>/fd/<n>` gelesen. Vor dem injizierten `close(n)` kann der Zielprozess den FD schließen und dieselbe Nummer für ein anderes Objekt wiederverwenden. Der Code prüft die Objektidentität unmittelbar vor `close` nicht erneut und stoppt nicht die gesamte Threadgruppe. Damit besteht mindestens ein plausibles Fehlentzugsrisiko. Dies muss entweder technisch reduziert und getestet oder als fundamentale Limitation des Prototyps dargestellt werden.

### TCB und Privilegien

Zur TCB gehören nicht nur die eBPF-Programme. Mindestens folgende Elemente sind vertrauenswürdig vorausgesetzt: Kernel/BPF-Verifier, Loader und eingebettetes Objekt, Policy-/Attributdateien, Watcher, gepinnte Maps, BPF-Link, Userspace-PEP, `ptrace`-Mechanismus, Administration der bpffs-Rechte und Build-/Deploymentprozess. `sudo -E` vergrößert die Bedeutung der Umgebungs- und Startkonfiguration. Die Arbeit braucht hierzu ein Diagramm und eine Tabelle.

## 3. Empfohlene Thesis-Aussagen

Die folgenden Reichweiten sind aus Code-Sicht vertretbar:

- **Nachgewiesen durch Code:** Es existiert eine eBPF-LSM-Tail-Call-Kette für `file_open`, welche vorbereitete Policies/Attribute aus Maps auswertet und Deny-Entscheidungen zurückgeben kann.
- **Durch Tests zu zeigen:** Die Kette wird vom Zielkernel akzeptiert; alle Policyarten liefern erwartete Entscheidungen; Generationenwechsel erscheinen konsistent; Kernel- und Userspace-Pfad stimmen für definierte Credentials überein.
- **Argumentativ plausibel:** Double Buffering reduziert die Sichtbarkeit partieller Updates; Device/Inode vermeidet Pfadstringvergleiche; Tail Calls modularisieren die eBPF-Programme.
- **Nicht gezeigt / nicht garantiert:** vollständige Vermittlung aller Dateinutzungen, sofortige Revocation, Schutz vor privilegierten Angreifern, race-freier FD-Entzug, vollständige Sicherheit oder allgemeine Produktionsreife.

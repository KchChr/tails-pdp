# Playbook für die Live-Demo

**Einstieg.** „Wir schauen uns drei Dinge an. Was passiert beim Öffnen einer Datei? Wie ändern Policies und Attribute die Entscheidung im laufenden Betrieb? Und was passiert mit Dateien, die ein Prozess schon offen hält?“

Starte auf der Demo-VM im Repository mit `./scripts/demo.sh`. Der Fokus bleibt links. **Enter: zum nächsten Teilschritt** zeigt die nächste Aktion an. **Enter: ausführen** startet sie. Lass das Ergebnis stehen, solange du es erklärst. **Strg+C** links bricht die Demo ab.

| Bereich | Worauf du zeigst |
| --- | --- |
| Links | Befehle, Dateiinhalt oder Fehlermeldung, aktive Policies und Attribute |
| Rechts oben | Runtime-Log, Kernel-Denys, Re-evaluation und Schließmeldungen des Userspace-PEP |
| Rechts unten | Ergebnisse und offene Dateideskriptoren des Bash-Prozesses |

## 1 · Runtime und Ausgangslage

**Sagen.** „Die Runtime startet mit leerem Policy-Stand. Wir prüfen zuerst, ob die Beispieldatei so lesbar ist.“

**Zeigen.** Admin-Tool ohne aktive Policy, UID und einmalig Gerät und Inode. `cat` gibt den Dateiinhalt aus.

## 2 · Statische Policy mit drei Filtern

**Sagen.** „Die Regel verweigert die Dateiöffnung, wenn UID, Kommando und Datei zusammenpassen. Wir ändern danach jeweils einen Faktor.“

| Schritt | Ergebnis zeigen |
| --- | --- |
| Vor der Policy | Beide Benutzer können die geschützte Datei lesen |
| Deny für Worker-UID, `cat` und geschützte Datei | `cat` meldet `Operation not permitted` |
| Andere UID, dann `head`, dann Kontrolldatei | Die drei einzelnen Gegenproben lesen den Inhalt |
| Hardlink zur geschützten Datei | `cat` wird wieder verweigert. Der andere Pfad verweist auf dieselbe Geräte- und Inode-Identität |
| Policy entfernen | Der ursprüngliche `cat`-Aufruf funktioniert wieder |

## 3 · Deny-Vorrang und Policy-Lebenszyklus

**Sagen.** „Für dieselbe Datei laden wir erst Permit und dann eine zusätzlich passende Deny-Regel.“

**Zeigen.** Dateiinhalt → Fehlermeldung → Dateiinhalt. Beim dritten Zugriff wurde nur die Deny-Policy entfernt. Permit bleibt zunächst aktiv und wird im letzten Schritt ebenfalls entfernt.

## 4 · Dynamisches Systemattribut

**Sagen.** „Die Deny-Regel bleibt geladen und prüft `system.defcon <= 2`. Wir ändern nur den Systemwert.“

**Zeigen.** `5 → 2 → 5` ergibt lesbar → verweigert → lesbar. Bei `2` auf den aktiven Wert im Admin-Tool zeigen. `echo` bereitet die Datei vor, `mv` veröffentlicht sie. Die Attributgeneration wechselt, während dieselbe Policy aktiv bleibt.

## 5 · System-, Subject- und Resource-Attribute

**Sagen.** „Alle drei Bedingungen müssen gleichzeitig stimmen. Die Regel prüft DEFCON, die Position des Benutzers und die Klassifizierung der Datei.“

**Zeigen.** Zuerst die drei Attributdateien. Bei DEFCON 2, Position `"engineer"` und Klassifizierung `"internal"` wird der Zugriff verweigert. `"intern"` oder `"public"` machen jeweils eine Bedingung falsch. Nach dem Zurücksetzen greift Deny wieder. Zeige zum Schluss die Attributdatei ohne Position und dann den Zahlenwert `1`. Beide erfüllen den Vergleich mit `"engineer"` nicht. Mit `"engineer"` greift Deny erneut.

## 6 · Ungültige Updates

**Sagen.** „Hier vergleichen wir im Admin-Tool, was nach einem fehlerhaften Update tatsächlich aktiv bleibt.“

1. Aktiven Stand mit `robust`, DEFCON 2 und beiden Generationen zeigen.
2. Policy mit fehlendem Semikolon veröffentlichen. Ablehnung im Log und unveränderte Generationen im Admin-Tool zeigen.
3. Fehlerhafte Datei entfernen, gültige Policy `corrected` laden und die neue Policygeneration zeigen. Danach `corrected` wieder entfernen.
4. DEFCON 9 veröffentlichen. Das Admin-Tool zeigt weiterhin 2 und dieselben Generationen wie direkt vor diesem Update.
5. DEFCON 5 veröffentlichen. Jetzt wechseln der aktive Wert und die Attributgeneration.

## 7 · Offene FDs durch eine neue Policy entziehen

**Sagen.** „Diese Bash öffnet Dateien zum Lesen und hält sie offen. Die Nummer eines offenen Eintrags heißt Dateideskriptor, kurz FD.“

**Vor dem nächsten Enter.** Auf die PID und `ls -l /proc/<PID>/fd` zeigen. Die Nummern **10, 11, 12** gehören zur geschützten Datei, **13, 14** zur Kontrolldatei. Jede Nummer steht für eine eigene Öffnung.

**Nach Veröffentlichung.** Rechts oben drei `USERSPACE_PEP closed`-Meldungen für dieselbe PID zeigen. In der FD-Liste fehlen 10, 11 und 12. 13 und 14 bleiben offen, und der Bash-Prozess läuft weiter.

## 8 · Offene FDs allein durch ein Attribut entziehen

**Sagen.** „Diesmal ist die Policy schon aktiv, wenn Bash die Dateien öffnet. Bei DEFCON 5 ist die Deny-Bedingung falsch.“

**Zeigen.** Zuerst fünf offene FDs. Dann per Enter DEFCON auf 2 setzen. Rechts oben den Attribut-Trigger und den Entzug zeigen. Die Policygeneration bleibt gleich, die Attributgeneration steigt. Rechts unten bleiben die beiden Kontroll-FDs offen.

## 9 · Wiederkehrendes Zeitfenster

**Sagen.** „`environment.time % 20 >= 10` teilt den Zyklus in zehn Sekunden ohne Deny und zehn Sekunden mit Deny. Bash versucht jede Sekunde zu öffnen, solange die Datei geschlossen ist.“

**Zeigen.** Rechts oben werden Öffnungsversuche während Deny abgewiesen. Rechts unten bleibt FD 10 während Permit offen. An der nächsten Deny-Grenze zeigt das PEP-Log den Entzug. Dieselbe PID versucht danach erneut zu öffnen. Die Konfigurationsgenerationen bleiben gleich. Der erste Abschnitt kann verkürzt sein. Nach dem Start bis zum zweiten bestätigten Entzug laufen lassen und auf den nächsten Enter-Hinweis warten.

## 10 · UTC-Felder in Policies

**Sagen.** „Zum Abschluss verwenden wir UTC-Minute und UTC-Stunde direkt als Policy-Bedingungen.“

**Zeigen.** Mit Permit und `environment.utc.minute >= 0` liest `cat` die Datei. Nach Veröffentlichung von Deny mit `environment.utc.hour >= 0` wird derselbe Aufruf verweigert. Beide Bedingungen sind den ganzen Tag wahr. Mit dem Admin-Tool die aktiven Regeln zeigen. Der erste Zugriff entspricht auch dem Standardverhalten ohne passende Deny-Regel. Der zweite zeigt, dass die UTC-Stundenbedingung greift und Deny Vorrang hat.

**Abschluss.** „Der Kernel kontrolliert neue Öffnungen. Der Userspace-PEP prüft bereits offene FDs bei Änderungen erneut. Beide Effekte waren direkt an den Befehlen, im Log und in der FD-Liste sichtbar.“

Bei einem Abbruch den angezeigten Diagnosepfad merken. Dort stehen die Ausgabe links in `transcript.log`, die Runtime-Meldungen in `runtime.log` und die Ausgaben des FD-Beobachters in `observer.log`.

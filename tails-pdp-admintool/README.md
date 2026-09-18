# tails-pdp-admintool

Die Administrationskomponente zeigt die geladenen `file_open`-Policies und
dynamischen Attribute des Prototyps an. Sie liest dazu die von `tails-pdp`
gepinnten eBPF-Maps und stellt deren Inhalte als Text im Terminal dar.

Das Tool arbeitet lesend: Es lädt, aktiviert, verändert oder löscht keine Policies
und Attribute. Änderungen an den Quelldateien werden durch die Loader des
Hauptprogramms verarbeitet. Die Ausgabe des Tools beschreibt den gespeicherten
Map-Zustand; sie ist kein Protokoll einzelner Dateiöffnungen.

## Voraussetzungen und Build

Die Map-Abfragen benötigen das Linux-Zielsystem, zugängliche Pins im
BPF-Dateisystem und ausreichende Berechtigungen. Die Beispiele verwenden `sudo`.
Für die Untersuchung des laufenden Prototyps muss `tails-pdp` auf demselben
Zielsystem gestartet sein. Vorhandene Pins allein beweisen nicht, dass das
Hauptprogramm oder die Zugriffsdurchsetzung noch aktiv sind.

Alle folgenden Shell-Beispiele werden **aus dem Repository-Hauptverzeichnis**
ausgeführt. Für einen nativen Build auf dem Linux-Zielsystem:

```bash
cargo build --release --package tails-pdp-admintool
```

Das erzeugte Programm liegt unter `target/release/tails-pdp-admintool`.
Die Einrichtung der Entwicklungsumgebung und das Cross-Compiling sind in der
[README des Gesamtprojekts](../README.md) beschrieben. Bei einem Build mit
explizitem `--target` liegt das Programm unter `target/<Zieltripel>/release/`.

Die Hilfe benötigt keine geladenen Maps:

```bash
./target/release/tails-pdp-admintool --help
```

Auch ein Aufruf ohne Argumente zeigt die Hilfe an.

## Befehle

```text
tails-pdp-admintool [OPTIONEN] <BEFEHL>
```

Pfadoptionen stehen **vor dem Unterbefehl**. Sie sind im aktuellen CLI nicht als
globale Optionen definiert. Die eigene Kurzhilfe zeigt eine abweichende
Reihenfolge; die Beispiele hier verwenden die vom Parser unterstützte Form.

| Befehl | Angezeigte Inhalte |
| --- | --- |
| `show` | Alle Plätze der aktuellen statischen und Stream-Policy-Bank, einschließlich deaktivierter Plätze, sowie Attribute der aktuellen Attributbank. |
| `show-active` | Nur Policy-Plätze mit `enabled != 0` aus der aktuellen Bank sowie Attribute der aktuellen Attributbank. |
| `show-policies` | Alle Plätze der aktuellen statischen und Stream-Policy-Bank, einschließlich deaktivierter Plätze; keine Attributwerte aus der Attribut-Map. |
| `show-attributes` | Nur Attribute der aktuellen Attributbank; keine Policy-Einträge. |

Jeder dieser Befehle gibt zunächst die Policy- und Attributgeneration sowie die
daraus bestimmten Bankinformationen aus. Auch `show-policies` benötigt deshalb
die Attributgenerations-Map; auch `show-attributes` benötigt die
Policy-Generations-Map.

### Gesamten Zustand anzeigen

```bash
sudo ./target/release/tails-pdp-admintool show
```

Dieser Aufruf eignet sich insbesondere zur Untersuchung der Belegung. Pro
Policy-Map werden aktuell 16 Plätze aus der ausgewählten Bank angezeigt.
Deaktivierte Plätze sind keine wirksamen Regeln, auch wenn ihre übrigen Felder
noch Werte enthalten.

### Nur aktivierte Policies und aktuelle Attribute anzeigen

```bash
sudo ./target/release/tails-pdp-admintool show-active
```

Dies ist der übersichtlichste Aufruf für die reguläre Kontrolle. „Aktiv“ meint
hier das `enabled`-Feld einer Policy. Es bedeutet nicht, dass diese Policy auf
einen bestimmten Zugriff zutrifft oder ihre Zeit- und Attributbedingungen gerade
erfüllt sind. Das Tool führt selbst keine Policy-Auswertung durch.

### Policies oder Attribute getrennt untersuchen

```bash
sudo ./target/release/tails-pdp-admintool show-policies
sudo ./target/release/tails-pdp-admintool show-attributes
```

`show-policies` zeigt auch die in Stream-Policies gespeicherten
Attributbedingungen. Die aktuellen Werte der Attribute erscheinen dagegen erst
bei `show-attributes`, `show` oder `show-active`.

## Optionen und Standardpfade

Die fünf Map-Pfade sind standardmäßig absolute Pfade unter
`/sys/fs/bpf/tails-pdp/`. Die beiden Quellverzeichnisse sind relativ zum
**Arbeitsverzeichnis des Aufrufs**, nicht zum Ort der ausführbaren Datei.

| Option | Standardwert | Zweck |
| --- | --- | --- |
| `--file-open-static-pin-path` | `/sys/fs/bpf/tails-pdp/FILE_OPEN_STATIC_POLICIES` | Map mit statischen Dateiöffnungs-Policies. |
| `--file-open-stream-pin-path` | `/sys/fs/bpf/tails-pdp/FILE_OPEN_STREAM_POLICIES` | Map mit dynamischen Dateiöffnungs-Policies. |
| `--policy-generation-pin-path` | `/sys/fs/bpf/tails-pdp/POLICY_GENERATION` | Aktuelle Policy-Generation. |
| `--attribute-generation-pin-path` | `/sys/fs/bpf/tails-pdp/ATTRIBUTE_GENERATION` | Aktuelle Attributgeneration. |
| `--attributes-pin-path` | `/sys/fs/bpf/tails-pdp/ATTRIBUTES` | Dynamische Attributwerte. |
| `--policy-dir` | `policies` | Policy-Dateien als Wörterbuch für lesbare Hash-Namen. |
| `--attributes-dir` | `attributes` | Attributdateien als Wörterbuch für lesbare Hash-Namen und Zeichenkettenwerte. |

Beispiel mit expliziten Quellverzeichnissen; die Pfade sind an die eigene
Installation anzupassen:

```bash
sudo ./target/release/tails-pdp-admintool \
  --policy-dir /srv/tails-pdp/policies \
  --attributes-dir /srv/tails-pdp/attributes \
  show-active
```

Beispiel für bereits unter einem anderen Verzeichnis vorhandene Pins:

```bash
sudo ./target/release/tails-pdp-admintool \
  --file-open-static-pin-path /sys/fs/bpf/demo/FILE_OPEN_STATIC_POLICIES \
  --file-open-stream-pin-path /sys/fs/bpf/demo/FILE_OPEN_STREAM_POLICIES \
  --policy-generation-pin-path /sys/fs/bpf/demo/POLICY_GENERATION \
  --attribute-generation-pin-path /sys/fs/bpf/demo/ATTRIBUTE_GENERATION \
  --attributes-pin-path /sys/fs/bpf/demo/ATTRIBUTES \
  show
```

Diese Optionen wählen bestehende Maps aus. Sie erzeugen keine Pins und ändern
nicht die Konfiguration des Hauptprogramms.

## Ausgabe verstehen

### Generationen und Bänke

Beispiel einer Kopfzeile:

```text
generation policy=3 policy_bank_offset=16 attribute=4 attribute_bank=0
```

Policy- und Attributgeneration werden unabhängig verwaltet. Für Policies gibt
es zwei Bänke mit jeweils 16 Plätzen pro Map. Der Offset berechnet sich als
`(policy_generation % 2) * 16`. Für Attribute wählt
`attribute_generation % 2` die Bank aus.

Alle vier Befehle lesen nur die so ausgewählte Bank. `show` zeigt also nicht
zusätzlich die inaktive Bank. Ein ausgegebener Policy-Index `[0]` ist relativ zur
ausgewählten Bank: Bei Offset 16 wurde dafür Map-Eintrag 16 gelesen.

### Statische Policies

Illustrative Ausgabe einer aktivierten Policy, keine Messung eines Testlaufs:

```text
FILE_OPEN_STATIC_POLICIES:
[0] enabled=1 entitlement=Deny subject=1000 command="cat" resource="/srv/demo.txt" device=2049 inode=12345
```

| Feld | Bedeutung |
| --- | --- |
| `[0]` | Platz innerhalb der ausgewählten Policy-Bank; kein ursprünglicher Policyname. |
| `enabled` | Null: deaktiviert; ungleich null: aktiviert. |
| `entitlement` | `Permit` oder `Deny`, also das Ergebnis dieser Regel bei erfüllten Bedingungen. |
| `subject` | Benutzerkennung für den Subjektfilter (Real UID); `any` steht für einen uneingeschränkten Subjektfilter. |
| `command` | Kommando-Filter anhand des Linux-Tasknamens `comm`; eine leere Zeichenkette bedeutet keinen Kommando-Filter. |
| `resource` | Gespeicherter Ressourcenpfad zur Darstellung. |
| `device`, `inode` | Aufgelöste Dateiidentität, anhand derer der Prototyp die Ressource abgleicht. Beide Werte null kennzeichnen eine uneingeschränkte Ressource. |

Die Felder beschreiben eine Regel. `entitlement=Permit` ist keine Aussage darüber,
ob eine konkrete Dateiöffnung insgesamt erlaubt wird: Eine ebenfalls passende
Deny-Policy hat bei der Zusammenführung Vorrang.

### Stream-Policies und Bedingungen

Illustrative Ausgabe:

```text
FILE_OPEN_STREAM_POLICIES:
[0] enabled=1 entitlement=Deny subject=any command="" resource="/srv/demo.txt" device=2049 inode=12345 legacy_condition=none
    attribute_condition=system.defcon LessThanOrEqual 2
```

Stream-Policies enthalten zusätzlich dynamische Bedingungen:

- `legacy_condition=none` bedeutet, dass keine gesonderte Stream-Zeitbedingung
  aktiviert ist. Attributbedingungen können trotzdem vorhanden sein.
- Eine Zeitbedingung kann beispielsweise als
  `legacy_condition=Time % 86400 GreaterThanOrEqual 64800` erscheinen. Die Ausgabe
  enthält den gespeicherten Modulo-Wert, Vergleichsoperator und Vergleichswert.
- Andere Stream-Zeitattribute werden als `Hour`, `Minute` oder `Second` dargestellt.
- Jede Zeile `attribute_condition=...` beschreibt eine strukturierte Bedingung an
  ein System-, Subjekt- oder Ressourcenattribut. Pro Policy werden höchstens vier
  solche Bedingungen ausgegeben.

Die Operatoren heißen in der Ausgabe `LessThan` (`<`), `LessThanOrEqual` (`<=`),
`Equal` (`==`), `GreaterThanOrEqual` (`>=`) und `GreaterThan` (`>`).
Zahlen erscheinen dezimal, boolesche Werte als `true` oder `false`, Zeichenketten
in Anführungszeichen. Die Ausgabe ist ein Diagnoseformat und keine direkt
einlesbare Policy-Datei.

### Attribute

Illustrative Ausgabe:

```text
ATTRIBUTES:
system.defcon = 3
subject:1000 subject.department = "research"
resource:2049:12345 resource.classification = "internal"
```

`system` bezeichnet globale Attribute, `subject:1000` Attribute des Subjekts mit
UID 1000 und `resource:2049:12345` Attribute einer Ressource mit der angegebenen
Device-/Inode-Kombination. Attribute werden nach Namespace, Objektidentität und
Namenshash sortiert; lesbare Namen sind daher nicht unbedingt alphabetisch
geordnet.

Das Tool zeigt die Attribut-Map, liest aber nicht die separate Zeit-Map
`CURRENT_TIME`. Der aktuelle Zeitwert für eine Zeitbedingung wird somit nicht
angezeigt.

## Lesbare Namen aus Quelldateien

Attributnamen und Zeichenkettenwerte sind in den Maps als Hashwerte gespeichert.
Für ihre lesbare Darstellung baut das Tool bei jedem Abfrageaufruf ein lokales
Wörterbuch aus folgenden Dateien auf:

- `attributes/system.attributes`;
- Dateien mit Endung `.attributes` direkt unter `attributes/subjects/`;
- Dateien mit Endung `.attributes` rekursiv unter `attributes/resources/`;
- Dateien mit Endung `.policy` rekursiv unter `policies/`.

Die Verzeichnisoptionen ändern die Ausgangspfade dieses Wörterbuchs. Das Tool
liest aus diesen Dateien Namen und Zeichenketten, lädt ihre Regeln oder Werte
aber nicht in die Maps. Auch bei `show-policies` und `show-attributes` werden
beide Wörterbuchquellen berücksichtigt.

Ist kein passender Text bekannt, erscheint stattdessen
`hash(...)` mit 32 hexadezimalen Stellen. Das bedeutet nicht automatisch, dass
ein Map-Eintrag ungültig ist. Häufig wird das Tool aus einem anderen
Arbeitsverzeichnis gestartet oder die passende Quelldatei fehlt.

Die Namensauflösung ist eine Darstellungshilfe und keine Rückübersetzung der
vollständigen Policy. Sie verwendet eine einfache Texterkennung, nicht den
vollständigen Policy-Parser. Fehlende Verzeichnisse können zu einem unvollständigen
Wörterbuch führen; Fehler beim Lesen vorhandener Dateien können den Aufruf
abbrechen. Die Quelldateien können außerdem bereits einen anderen Stand als die
geladenen Maps haben.

## Typische Diagnoseabläufe

Nach einer Policy- oder Attributänderung kann der geladene Zustand erneut
angezeigt werden:

```bash
sudo ./target/release/tails-pdp-admintool show-active
```

Dabei zuerst die Generationen und anschließend die erwarteten Regeln und Werte
prüfen. Ein geänderter Quelltext allein bestätigt noch keine erfolgreiche
Aktivierung durch den Loader.

Für einen Vergleich zweier Zustände kann die Ausgabe gespeichert werden:

```bash
sudo ./target/release/tails-pdp-admintool show-active > /tmp/tails-pdp-before.txt
# Nach der gewünschten Änderung und ihrer Aktivierung erneut ausführen:
sudo ./target/release/tails-pdp-admintool show-active > /tmp/tails-pdp-after.txt
diff -u /tmp/tails-pdp-before.txt /tmp/tails-pdp-after.txt
```

Nur die reguläre Ausgabe wird umgeleitet; Fehlermeldungen bleiben auf stderr.
Es gibt keinen eingebauten Watch-Modus, JSON-Export oder Befehl zur Simulation
einer konkreten Zugriffsentscheidung.

## Grenzen der Nachvollziehbarkeit

Die Generationen werden zu Beginn des Aufrufs jeweils einmal gelesen. Das Tool
prüft nach dem Auslesen nicht erneut, ob sich diese verändert haben. Bei
gleichzeitigen Aktualisierungen ist die Ausgabe deshalb kein garantiert
konsistenter Gesamtschnappschuss. Für reproduzierbare Vergleiche sollten während
des Auslesens keine Policy- oder Attributänderungen erfolgen.

Die Anzeige enthält weder eine Historie einzelner Zugriffe noch eine direkte
Zuordnung der Map-Indizes zu ursprünglichen Policynamen. Sie zeigt auch nicht,
welche Regel bei einer bestimmten früheren Dateiöffnung tatsächlich ausschlaggebend
war. Dafür müssen zusätzlich die Laufzeitmeldungen beziehungsweise die optionalen
Kernel-Debug-Ausgaben betrachtet werden; siehe
[Debugging im Gesamtprojekt](../README.md#debugging).

## Fehlerbehebung

| Beobachtung | Prüfung |
| --- | --- |
| `failed to open pinned map at ...` | Existiert der Pin? Stimmen Pfad und Berechtigungen? Hat das Hauptprogramm die benötigten Maps bereitgestellt? |
| Fehler beim Interpretieren oder Lesen einer Map | Passen die Map-Typen und Datenlayouts zum gebauten Administrationsprogramm? Hauptprogramm und Tool sollten aus einem kompatiblen Codestand stammen. |
| Nur `hash(...)` statt Namen | Arbeitsverzeichnis sowie `--policy-dir` und `--attributes-dir` prüfen; die passenden Quelldateien müssen für die Namensauflösung verfügbar sein. |
| Keine Policy-Zeilen bei `show-active` | Mit `show-policies` die Plätze der aktuellen Bank und deren `enabled`-Felder untersuchen. |
| Geänderte Datei, aber alte Map-Werte | Die Meldungen des Hauptprogramms auf Parser-, Lade- oder Aktivierungsfehler prüfen. Das Administrationsprogramm übernimmt selbst keine Änderungen. |
| Option wird nach dem Befehl zurückgewiesen | Optionen vor den Unterbefehl stellen, beispielsweise `--policy-dir /srv/tails-pdp/policies show-active`. |

Erfolgreiche Aufrufe enden mit Exitcode 0, ungültige CLI-Argumente mit Exitcode 2.
Laufzeitfehler werden an `main` zurückgegeben und führen zu einem Fehlerabschluss
(Exitcode 1). Bereits gedruckte Zeilen können dabei vorhanden sein; eine teilweise
Ausgabe ist kein Beleg für einen erfolgreichen vollständigen Aufruf.

## Aufbau des Crates

| Datei | Verantwortung |
| --- | --- |
| [`src/main.rs`](src/main.rs) | Einstiegspunkt und Rückgabe von Fehlern. |
| [`src/cli.rs`](src/cli.rs) | Befehle, Optionen und Standardpfade. |
| [`src/lib.rs`](src/lib.rs) | Befehlsausführung, Lesen der Generationen und Aufbau des Hash-Wörterbuchs. |
| [`src/maps.rs`](src/maps.rs) | Öffnen und typisierter Zugriff auf die gepinnten Maps. |
| [`src/output.rs`](src/output.rs) | Filterung, Sortierung und Textdarstellung der Map-Inhalte. |

Die gemeinsamen Datenstrukturen und Kapazitätsgrenzen liegen im Crate
[`tails-pdp-common`](../tails-pdp-common/).

# Dynamic Attributes - Änderungsübersicht

Stand: 2026-06-08

Diese Übersicht beschreibt die Implementierung der frei definierbaren Attribute für `system.*` und
`subject.*`, den Datenfluss in die eBPF Maps und die wichtigsten Designentscheidungen.

## Ziel

Policies sollen Attribute verwenden können, deren Namen und Werte nicht vorher im Code bekannt sind.
Beispiele:

```sapl
subject.position == "engineer";
subject.access-level >= 3;
system.defcon <= 3;
system.maintenance_mode == false;
```

Die Attributwerte werden in Userspace-Dateien gepflegt und bei Änderungen in gepinnte eBPF Maps
geschrieben, damit Kernel-Programme und der Userspace-Monitor denselben Zustand auswerten können.

## Datenmodell und ABI

Code:

- `tails-pdp-common/src/lib.rs:17`: `ATTRIBUTE_BANK_COUNT`
- `tails-pdp-common/src/lib.rs:18`: `ATTRIBUTE_MAP_MAX_ENTRIES`
- `tails-pdp-common/src/lib.rs:19`: `ATTRIBUTE_GENERATION_MAX_ENTRIES`
- `tails-pdp-common/src/lib.rs:20`: `MAX_ATTRIBUTE_CONDITIONS`
- `tails-pdp-common/src/lib.rs:97`: `AttributeNamespace`
- `tails-pdp-common/src/lib.rs:104`: `AttributeValueKind`
- `tails-pdp-common/src/lib.rs:112`: `AttributeHash`
- `tails-pdp-common/src/lib.rs:125`: `AttributeKey`
- `tails-pdp-common/src/lib.rs:152`: `AttributeValue`
- `tails-pdp-common/src/lib.rs:190`: `AttributeCondition`
- `tails-pdp-common/src/lib.rs:216`: `attribute_hash`

Sinn:

Die neuen Attribute werden in einem gemeinsamen ABI-Crate definiert, damit Userspace, Monitor und
eBPF exakt dieselben C-kompatiblen Strukturen verwenden. Das ist wichtig, weil eBPF Map-Key und
Map-Value binäre Layouts sind. Unterschiedliche Struct-Layouts zwischen Kernel- und Userspace-Seite
würden zu falschen Lookups oder Load-Fehlern führen.

Gedanke dahinter:

eBPF kann keine dynamischen Strings oder beliebige Heap-Strukturen sinnvoll auswerten. Deshalb werden
Attributnamen und Stringwerte vor dem Schreiben in die Map stabil gehasht. Zahlen und Booleans werden
direkt als `u64` gespeichert. Dadurch bleibt die eBPF-Auswertung klein, deterministisch und
verifier-freundlich.

Aktuelle Grenzen:

- Maximal `MAX_ATTRIBUTE_CONDITIONS = 4` dynamische Attributbedingungen pro Stream-Policy.
- `ATTRIBUTES` hat aktuell `ATTRIBUTE_MAP_MAX_ENTRIES = 1024`.
- Stringvergleiche unterstützen nur `==`.
- Attributnamen sind frei, aber syntaktisch begrenzt auf ASCII-Buchstaben, Ziffern, `_` und `-`.

## Stream-Policy-Erweiterung

Code:

- `tails-pdp-common/src/lib.rs:412`: `FileOpenStreamPolicy`
- `tails-pdp-common/src/lib.rs:420`: `stream_condition_enabled`
- `tails-pdp-common/src/lib.rs:421`: `attribute_condition_count`
- `tails-pdp-common/src/lib.rs:430`: `attribute_conditions`
- `tails-pdp-common/src/lib.rs:455`: `FileOpenStreamPolicy::stream`
- `tails-pdp-common/src/lib.rs:604`: `SocketBindStreamPolicy`
- `tails-pdp-common/src/lib.rs:614`: `stream_condition_enabled`
- `tails-pdp-common/src/lib.rs:615`: `attribute_condition_count`
- `tails-pdp-common/src/lib.rs:625`: `attribute_conditions`
- `tails-pdp-common/src/lib.rs:653`: `SocketBindStreamPolicy::stream`

Sinn:

Stream-Policies können neben den eingebauten Zeitbedingungen auch dynamische Attributbedingungen
tragen. DEFCON wird im aktuellen Stand als strukturiertes Systemattribut `system.defcon` behandelt.

Gedanke dahinter:

Die Policies bleiben feste Arrays in eBPF Maps. Statt eine dynamische Liste zu speichern, enthält
jede Policy ein kleines festes Array von `AttributeCondition`. Das vermeidet Heap-Allokationen und
unbegrenzte Schleifen im eBPF-Programm.

## Vergleichslogik

Code:

- `tails-pdp-common/src/lib.rs:909`: `matches_attribute_condition`
- `tails-pdp-common/src/lib.rs:927`: `attribute_object_id`
- `tails-pdp-common/src/lib.rs:958`: `file_open_stream_policy_applies_to_request`
- `tails-pdp-common/src/lib.rs:982`: `file_open_stream_legacy_entitlement`
- `tails-pdp-common/src/lib.rs:1045`: `socket_bind_stream_policy_applies_to_request`
- `tails-pdp-common/src/lib.rs:1070`: `socket_bind_stream_legacy_entitlement`

Sinn:

Gemeinsame Hilfsfunktionen trennen drei Prüfschritte:

1. Passt die Policy statisch zur Anfrage, zum Beispiel UID, Command und Resource?
2. Passen die dynamischen Attribute?
3. Passt die eingebaute Stream-Bedingung, falls vorhanden?

Gedanke dahinter:

Die statische Filterlogik soll nicht in eBPF, Monitor und Tests auseinanderlaufen. Deshalb liegt sie
in `tails-pdp-common`. Die vollständige dynamische Auswertung kann aber nicht in den alten
`evaluate_*_stream_policy`-Funktionen passieren, weil diese keinen Zugriff auf die `ATTRIBUTES` Map
haben. Darum geben diese Funktionen bei dynamischen Conditions bewusst `None` zurück.

## Gepinnte eBPF Maps

Code:

- `tails-pdp-ebpf/src/maps.rs:63`: `ATTRIBUTE_GENERATION`
- `tails-pdp-ebpf/src/maps.rs:67`: `ATTRIBUTES`
- `tails-pdp/src/policy_loader.rs:57`: `verify_pinned_map_layouts`
- `tails-pdp/src/policy_loader.rs:106`: Layoutprüfung für `ATTRIBUTE_GENERATION`
- `tails-pdp/src/policy_loader.rs:112`: Layoutprüfung für `ATTRIBUTES`

Sinn:

Die Attribute liegen in gepinnten Maps, damit der Monitor die Policies und Attribute aus Userspace
überwachen kann. Neue Maps:

- `ATTRIBUTE_GENERATION`: aktiver Attribut-Generation-Zähler
- `ATTRIBUTES`: HashMap mit `AttributeKey -> AttributeValue`

Gedanke dahinter:

Die Policy Maps waren bereits gepinnt. Für den Monitor muss dasselbe für die Attribut Maps gelten,
sonst könnte nur das geladene eBPF-Programm die Attribute sehen. Die Layoutprüfung verhindert, dass
alte gepinnte Maps mit inkompatiblen Key-/Value-Größen still weiterverwendet werden.

Wichtig für das Zielsystem:

Nach diesem ABI-Wechsel müssen alte Pins ggf. entfernt werden, bevor `run.sh` startet:

```sh
sudo rm -f /sys/fs/bpf/tails-pdp/ATTRIBUTES
sudo rm -f /sys/fs/bpf/tails-pdp/ATTRIBUTE_GENERATION
```

## Attributdateien und Loader

Code:

- `tails-pdp/src/stream_attributes.rs:17`: Runtime-Verzeichnis `attributes`
- `tails-pdp/src/stream_attributes.rs:19`: `system.attributes`
- `tails-pdp/src/stream_attributes.rs:20`: `subjects`
- `tails-pdp/src/stream_attributes.rs:53`: Öffnen der `ATTRIBUTES` und `ATTRIBUTE_GENERATION` Maps
- `tails-pdp/src/stream_attributes.rs:77`: initiales Schreiben der Attribute
- `tails-pdp/src/stream_attributes.rs:100`: Watcher für Attributänderungen
- `tails-pdp/src/stream_attributes.rs:140`: Default-Struktur anlegen
- `tails-pdp/src/stream_attributes.rs:224`: Attributverzeichnis einlesen
- `tails-pdp/src/stream_attributes.rs:264`: `.attributes` Datei parsen
- `tails-pdp/src/stream_attributes.rs:308`: Attributnamen validieren
- `tails-pdp/src/stream_attributes.rs:321`: Attributwerte parsen
- `tails-pdp/src/stream_attributes.rs:366`: Commit in die Maps
- `tails-pdp/src/stream_attributes.rs:407`: inaktive Bank bereinigen

Sinn:

Die Runtime-Umgebung sieht so aus:

```text
attributes/
  system.attributes
  subjects/
    1000.attributes
    1001.attributes
```

`system.attributes` enthält globale Attribute. `subjects/<uid>.attributes` enthält Attribute für genau eine UID.
Änderungen werden rekursiv beobachtet und nach kurzem Debounce neu in die eBPF Maps geschrieben.

Gedanke dahinter:

Das Format bleibt bewusst einfach:

```ini
defcon = 3
maintenance_mode = false
position = "engineer"
access-level = 3
```

Attributnamen müssen nicht vorher bekannt sein. Sie werden beim Einlesen gehasht. Die Policy nutzt
denselben Hash, dadurch treffen sich Policy-Bedingung und Attributwert in der Map.

## Atomic Update über Generationen

Code:

- `tails-pdp-common/src/lib.rs:34`: `attribute_bank`
- `tails-pdp/src/stream_attributes.rs:370`: aktuelle Generation lesen
- `tails-pdp/src/stream_attributes.rs:371`: nächste Generation bestimmen
- `tails-pdp/src/stream_attributes.rs:372`: inaktive Bank berechnen
- `tails-pdp/src/stream_attributes.rs:374`: inaktive Bank löschen
- `tails-pdp/src/stream_attributes.rs:376`: Attribute in inaktive Bank schreiben
- `tails-pdp/src/stream_attributes.rs:394`: `ATTRIBUTE_GENERATION[0]` committen

Sinn:

Der Kernel soll nie einen halb geschriebenen Attributzustand sehen.

Gedanke dahinter:

Die Attribute werden in die gerade inaktive Bank geschrieben. Erst ganz am Ende wird
`ATTRIBUTE_GENERATION[0]` erhöht. eBPF liest daraus die aktive Bank. Dieses Muster entspricht dem
bereits vorhandenen Policy-Banking und ist für eBPF deutlich robuster als ein direktes In-Place-Update.

## Policy Parser

Code:

- `tails-pdp/src/policy_source.rs:45`: `ParsedStreamCondition`
- `tails-pdp/src/policy_source.rs:68`: dynamische Condition-Variante
- `tails-pdp/src/policy_source.rs:83`: mehrere Stream-Conditions pro Policy
- `tails-pdp/src/policy_source.rs:847`: dynamische Attribute in Stream-Parser einhängen
- `tails-pdp/src/policy_source.rs:854`: `parse_dynamic_attribute_condition`
- `tails-pdp/src/policy_source.rs:889`: Vergleichsoperatoren parsen
- `tails-pdp/src/policy_source.rs:907`: Attributnamen validieren
- `tails-pdp/src/policy_source.rs:920`: dynamische Attributwerte parsen
- `tails-pdp/src/policy_source.rs:1076`: eingebaute und dynamische Conditions trennen
- `tails-pdp/src/policy_source.rs:1100`: Limit für dynamische Conditions
- `tails-pdp/src/policy_source.rs:1141`: Attribute in File-Open-Policy schreiben

Sinn:

Policies können jetzt Bedingungen wie `subject.position == "engineer"` und `system.defcon <= 3`
verwenden. Das gilt zusätzlich zu bestehenden Stream-Bedingungen.

Gedanke dahinter:

`subject.uid` bleibt ein eingebautes Feld und wird nicht als dynamisches Attribut behandelt. Alle
anderen `subject.<name>` und `system.<name>` Attribute gehen über die neue Hash-/Map-Logik. Damit
bleiben vorhandene Policies kompatibel und neue Attribute müssen nicht im Code registriert werden.

## eBPF-Auswertung

Code:

- `tails-pdp-ebpf/src/policies/file_open_stream_policies.rs:40`: Stream-Policy-Iteration
- `tails-pdp-ebpf/src/policies/file_open_stream_policies.rs:43`: statischer Match
- `tails-pdp-ebpf/src/policies/file_open_stream_policies.rs:44`: dynamische Attribute prüfen
- `tails-pdp-ebpf/src/policies/file_open_stream_policies.rs:50`: eingebaute Stream-Condition prüfen
- `tails-pdp-ebpf/src/policies/file_open_stream_policies.rs:95`: Attribut-Lookup für File-Open
- `tails-pdp-ebpf/src/policies/file_open_stream_policies.rs:140`: aktive Attributbank lesen
- `tails-pdp-ebpf/src/policies/socket_bind_stream_policies.rs:42`: Stream-Policy-Iteration
- `tails-pdp-ebpf/src/policies/socket_bind_stream_policies.rs:45`: statischer Match
- `tails-pdp-ebpf/src/policies/socket_bind_stream_policies.rs:46`: dynamische Attribute prüfen
- `tails-pdp-ebpf/src/policies/socket_bind_stream_policies.rs:52`: eingebaute Stream-Condition prüfen
- `tails-pdp-ebpf/src/policies/socket_bind_stream_policies.rs:98`: Attribut-Lookup für Socket-Bind
- `tails-pdp-ebpf/src/policies/socket_bind_stream_policies.rs:143`: aktive Attributbank lesen

Sinn:

Die eBPF-Programme werten dynamische Attribute direkt im LSM-Hook aus. Fehlt ein benötigtes Attribut
oder passt der Wert nicht, gilt die Policy als nicht zutreffend.

Gedanke dahinter:

Die eBPF-Seite macht nur bounded Loops bis `MAX_ATTRIBUTE_CONDITIONS`, baut einen festen
`AttributeKey` und macht Map-Lookups. Es gibt keinen Heap, keine dynamische Stringverarbeitung und
keine unbounded Iteration. Das reduziert Verifier-Risiken bei Stack und Program Complexity.

## Monitor

Code:

- `tails-pdp/src/monitor.rs:162`: gepinnte Policy- und Attributmaps öffnen
- `tails-pdp/src/monitor.rs:188`: `ATTRIBUTE_GENERATION` öffnen
- `tails-pdp/src/monitor.rs:192`: `ATTRIBUTES` öffnen
- `tails-pdp/src/monitor.rs:233`: aktive Attributbank bestimmen
- `tails-pdp/src/monitor.rs:326`: File-Open-Stream-Policies mit Attributen prüfen
- `tails-pdp/src/monitor.rs:434`: Socket-Bind-Stream-Policies mit Attributen prüfen
- `tails-pdp/src/monitor.rs:461`: Monitor-seitiger Attributvergleich

Sinn:

Der Monitor sieht dieselben dynamischen Attribute wie das eBPF-Programm und kann daher auch
Userspace-seitig Policy-Verletzungen für bereits offene Ressourcen erkennen.

Gedanke dahinter:

Der Monitor liest die gepinnten Maps aus `/sys/fs/bpf/tails-pdp`. Dadurch muss kein separater
Userspace-Zustand dupliziert werden. Policy-Auswertung und Attributzustand bleiben auf demselben
Map-Stand.

## Start-Workflow

Code:

- `tails-pdp/src/main.rs:36`: Pin-Verzeichnis anlegen
- `tails-pdp/src/main.rs:38`: gepinnte Map-Layouts prüfen
- `tails-pdp/src/main.rs:81`: Zeitmaps öffnen
- `tails-pdp/src/main.rs:82`: DEFCON-Map öffnen
- `tails-pdp/src/main.rs:83`: Attributmaps öffnen
- `tails-pdp/src/main.rs:112`: Policies initial synchronisieren
- `tails-pdp/src/main.rs:115`: Attribute initial schreiben
- `tails-pdp/src/main.rs:136`: parallele Watcher starten
- `tails-pdp/src/main.rs:139`: Attribut-Watcher im `tokio::select!`

Sinn:

Beim Start werden Policies, Zeitwerte, DEFCON und strukturierte Attribute initial geschrieben, bevor
die Watcher weiterlaufen. Danach hält der Prozess die Maps aktuell.

Gedanke dahinter:

Das passt zum vorhandenen Zielsystem-Workflow: `run.sh` startet das System, der Userspace-Prozess
lädt eBPF, pinnt Maps und überwacht danach Policies und Attributdateien.

## Beispiele und Dokumentation

Code/Dokumentation:

- `README.md:96`: unterstützte Stream Conditions
- `README.md:109`: Beschreibung von `system.<attribute>` und `subject.<attribute>`
- `attributes/README.md:8`: Runtime-Dateien für strukturierte Attribute
- `examples/25-file-open-stream-deny-engineer-defcon-le-3.sapl:1`: Beispielpolicy
- `examples/attributes/system.attributes:1`: Beispiel für Systemattribute
- `examples/attributes/subjects/1000.attributes:1`: Beispiel für Subject UID 1000
- `examples/attributes/subjects/1001.attributes:1`: Beispiel für Subject UID 1001

Sinn:

Es gibt jetzt sowohl aktive Runtime-Beispiele in `attributes/` als auch kopierbare Beispiele unter
`examples/attributes/`.

Gedanke dahinter:

`examples/` soll nicht automatisch aktiv werden. Die Dateien dort sind Vorlagen. Aktiv ist nur das
Runtime-Verzeichnis `attributes/`, das vom laufenden Prozess beobachtet wird.

## Tests und Build-Prüfung

Ausgeführt am 2026-06-08:

```sh
cargo fmt --all -- --check
cargo test -p tails-pdp-common --config 'target."cfg(all())".runner="env"'
cargo check-linux-x86_64
cargo build-linux-x86_64
```

Ergebnis:

- Formatierung erfolgreich.
- `tails-pdp-common` Tests erfolgreich, 12 Tests.
- Linux-Cross-Check erfolgreich.
- Linux-Release-Cross-Build erfolgreich.

Hinweis:

Auf macOS kann der echte Linux Kernel Load/Verifier-Lauf nicht ausgeführt werden. Der Cross-Build
kompiliert aber Userspace und eBPF-Artefakt für das Zielsystem.

## Risiken und offene Punkte

Hash-Kollisionen:

Attributnamen und Stringwerte werden gehasht. Das ist eBPF-tauglich, aber theoretisch können
Kollisionen auftreten. Für die aktuelle Thesis-/Demonstrator-Größe ist das pragmatisch vertretbar.

Map-Kapazität:

`ATTRIBUTE_MAP_MAX_ENTRIES = 1024` umfasst beide Banken zusammen. Viele UIDs mit vielen Attributen
können diese Grenze erreichen.

String-Operatoren:

Strings unterstützen nur `==`. Größer/kleiner-Vergleiche sind für gehashte Strings nicht sinnvoll.

Verifier/Stack:

Die eBPF-Seite vermeidet Heap und dynamische Datenstrukturen. Die relevante Begrenzung ist aktuell
bewusst klein gehalten: maximal vier dynamische Attributbedingungen pro Policy, feste Structs und
bounded Loops. Das reduziert Stack- und Verifier-Risiken.

Zielsystem:

Wegen neuer gepinnter Maps und geänderter Stream-Policy-Structs können alte Pins inkompatibel sein.
Die Layoutprüfung erkennt das und fordert zum Entfernen der stale pinned map auf.

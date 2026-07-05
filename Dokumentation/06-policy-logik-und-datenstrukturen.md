# Policy-Logik und Datenstrukturen

## Gemeinsame Logik

Die zentrale Policy-Logik liegt in [`tails-pdp-common/src/lib.rs`](../tails-pdp-common/src/lib.rs). Dieses Crate wird von Userspace
und eBPF genutzt. Dadurch sollen beide Seiten dieselbe Entscheidung treffen [[P8]](../tails-pdp-common/src/lib.rs). Die textuellen
ASBAC-Policies werden in projektspezifische Rust-Structs übersetzt [[P3]](../tails-pdp-policy-loader/src/policy_source.rs).

Stream Policies enthalten dynamische Bedingungen und dürfen zusätzlich die statischen Filter des
Hooks mitbenutzen. Eine `file_open`-Stream-Policy
kann also `subject`, `command` und `resource.path` mit `system.defcon` oder `environment.utc.hour`
kombinieren [[P3]](../tails-pdp-policy-loader/src/policy_source.rs), [[P8]](../tails-pdp-common/src/lib.rs).

Wichtige Funktionen:

| Funktion | Zweck |
| --- | --- |
| `evaluate_file_open_static_policy` | Prüft eine Static Policy für Dateiöffnungen. |
| `evaluate_file_open_stream_policy` | Prüft eine Stream Policy für Dateiöffnungen. |
| `matches_stream_operator` | Vergleicht Werte mit `<`, `<=`, `==`, `>=`, `>`. |

## Vollständiger Policy-Ladeprozess

Der Policy-Ladeprozess läuft vollständig im Userspace. Der Kernel erhält keine Textdateien,
sondern ausschließlich validierte Strukturen mit fester Größe. Der zentrale Code steht in
[`tails-pdp-policy-loader/src/policy_source.rs`](../tails-pdp-policy-loader/src/policy_source.rs)
[[P3]](../tails-pdp-policy-loader/src/policy_source.rs).

```text
policies/**/*.policy
        |
        v
Dateien rekursiv lesen und sortieren
        |
        v
Syntax in ParsedPolicy parsen
        |
        v
Semantik und eBPF-Grenzen validieren
        |
        v
FileOpenStaticPolicy / FileOpenStreamPolicy erzeugen
        |
        v
inaktive Policy-Bank vollständig schreiben
        |
        v
POLICY_GENERATION als Commit-Punkt umschalten
        |
        v
eBPF und Userspace-PEP verwenden die neue Generation
```

### 1. Initialisierung

Das Hauptprogramm erzeugt zunächst `PolicyDirectorySync`. Der Konstruktor:

1. bestimmt `<aktuelles Arbeitsverzeichnis>/policies`,
2. legt das Verzeichnis bei Bedarf an,
3. öffnet die gepinnten Maps `POLICY_GENERATION`, `FILE_OPEN_STATIC_POLICIES` und
   `FILE_OPEN_STREAM_POLICIES`,
4. initialisiert den Vergleichszustand für erfolgreiche und fehlerhafte Dateistände.

Die Maps müssen zu diesem Zeitpunkt bereits durch den eBPF-Loader erstellt oder aus dem BPF-
Dateisystem wieder geöffnet worden sein. Das eigentliche initiale Lesen beginnt erst mit
`PolicyDirectorySync::sync_initial` in [`tails-pdp/src/main.rs`](../tails-pdp/src/main.rs) [[P1]](../tails-pdp/src/main.rs).

Eine ungültige initiale Policy-Konfiguration bricht den Programmstart ab. Der LSM-Hook wird erst
nach einer erfolgreichen initialen Policy-, Zeit- und Attributsynchronisation angehängt. Dadurch
wird keine unvollständig initialisierte Policy-Engine aktiviert.

### 2. Policy-Dateien einlesen

`read_policy_documents` durchsucht `policies/` rekursiv. Berücksichtigt werden ausschließlich
Dateien mit der Endung `.policy`. Für jede Datei entsteht eine interne Darstellung:

```rust
PolicyDocument {
    relative_path,
    source,
}
```

Der relative Pfad dient der Diagnose und der vollständige Dateiinhalt dem Parser. Die Dokumente
werden nach ihrem relativen Pfad sortiert. Damit bleibt die Übersetzungs- und Map-Reihenfolge über
mehrere Läufe hinweg deterministisch.

`PolicyDirectorySync` speichert die vollständigen Dokumentvektoren als `last_applied_documents`
und `last_failed_documents`. Dadurch werden weder ein unveränderter gültiger Stand noch derselbe
bereits abgelehnte Stand unnötig erneut verarbeitet.

### 3. Zeilenbasierte Syntax parsen

`parse_policy_document` verarbeitet jede Policydatei einzeln. Leere Zeilen sowie Zeilen, die mit
`//` oder `#` beginnen, werden ignoriert. Die erste relevante Zeile muss einen Namen enthalten:

```sapl
policy "deny cat on test file"
```

Die zweite relevante Zeile muss das Entitlement festlegen:

```sapl
deny
```

oder:

```sapl
permit
```

Alle folgenden relevanten Zeilen werden als einzelne Statements verarbeitet und müssen mit `;`
enden. Der Parser erkennt insbesondere:

| Statement | Interne Bedeutung |
| --- | --- |
| `action == "file_open";` | `PolicyAction::FileOpen` |
| `subject.uid == 1000;` | konkrete Subjekt-UID |
| `command == "cat";` | Prozessnamensfilter |
| `resource.path == "/home/hntr/test.txt";` | Dateiressource |
| `environment.time % 10 < 5;` | modulo-basierte Zeitbedingung |
| `environment.utc.hour >= 16;` | UTC-Zeitkomponente |
| `subject.position == "engineer";` | dynamisches Subjektattribut |
| `system.defcon <= 2;` | dynamisches Systemattribut |
| `resource.classification == "internal";` | dynamisches Ressourcenattribut |

Unbekannte Statements, fehlende Semikolons, ungültige Zahlen und nicht unterstützte Operatoren
führen zu einem Fehler mit Dateipfad und Zeilennummer. Felder wie `action`, `subject.uid`, `command`
oder `resource.path` dürfen innerhalb einer Policy nur einmal vorkommen. `set_once` erkennt solche
Doppeldefinitionen.

`action` ist verpflichtend. Für optionale Filter gelten folgende Defaults:

| Feld | Default und Bedeutung |
| --- | --- |
| `subject.uid` | `ANY_SUBJECT`, also jede UID |
| `command` | leer, also jedes Kommando |
| `resource.path` | leer, also jede Datei |

Das Ergebnis ist zunächst `ParsedPolicy`. Dieser Userspace-Typ darf noch `String`, `Option` und
`Vec` enthalten und wird nicht direkt in eine BPF-Map geschrieben.

### 4. Dokumentübergreifende Validierung

`translate_policy_documents` führt alle geparsten Policies zusammen. Policy-Namen müssen über das
gesamte rekursiv gelesene Verzeichnis eindeutig sein. Ein doppelter Name verwirft den vollständigen
neuen Policy-Stand.

Die Einteilung in Static und Stream erfolgt anhand der Bedingungen:

- keine Stream-Bedingung: `FileOpenStaticPolicy`,
- mindestens eine Zeit- oder dynamische Attributbedingung: `FileOpenStreamPolicy`.

Der Parser kennt Bezeichner für `socket_bind`, die Übersetzung lehnt `socket_bind` derzeit jedoch
explizit ab. Ebenso werden Socket-Felder in einer `file_open`-Policy abgelehnt. Produktiv geladen
werden aktuell ausschließlich `file_open`-Policies.

### 5. eBPF- und Map-Grenzen validieren

Vor der Übersetzung in gemeinsame Strukturen prüft der Loader die festen Grenzen des Map-ABI:

- `command` darf höchstens `COMMAND_LEN = 16` Bytes enthalten,
- `resource.path` darf höchstens `RESOURCE_LEN = 64` Bytes enthalten,
- pro Bank sind höchstens 16 Static-Policies zulässig,
- pro Bank sind höchstens 16 Stream-Policies zulässig,
- pro Stream-Policy ist höchstens eine eingebaute Zeitbedingung zulässig,
- pro Stream-Policy sind höchstens vier dynamische Attributbedingungen zulässig.

Die Längen beziehen sich auf UTF-8-Bytes, nicht auf die sichtbare Zeichenanzahl. Diese Prüfung ist
notwendig, weil die gemeinsamen Map-Strukturen feste Byte-Arrays statt dynamischer Strings nutzen.

### 6. Dateiressource in Kernelidentität übersetzen

Ein Pfad wird im Userspace mit `fs::metadata` aufgelöst. In die kernelgeeignete Policy werden
zusätzlich eingetragen:

- die Linux-Device-ID,
- die Inode der Datei.

Die gemeinsame Funktion `resolve_resource_identity` steht in
[`tails-pdp-common/src/lib.rs`](../tails-pdp-common/src/lib.rs) [[P8]](../tails-pdp-common/src/lib.rs). Der eBPF-Hook muss dadurch
keinen vollständigen Pfad aufbauen oder vergleichen. Ein leerer Ressourcenpfad bleibt als
`device = 0, inode = 0` eine Wildcard. Ein konfigurierter Pfad muss beim Laden existieren; andernfalls
schlägt die neue Policy-Generation fehl.

Diese Identität hat fachliche Folgen: Hardlinks auf dieselbe Inode werden gleich behandelt. Wird
eine Datei gelöscht und neu erstellt, kann sich ihre Inode ändern und die Policy muss neu geladen
werden.

### 7. Stream- und Attributbedingungen übersetzen

Eingebaute Zeitbedingungen werden als `StreamAttribute`, `StreamOperator`, `modulo` und `value`
gespeichert. Unterstützt werden Unix-Zeit modulo sowie UTC-Stunde, -Minute und -Sekunde.

Dynamische Bedingungen werden zu `AttributeCondition`. Der Namespace wird aus dem Präfix
`system.`, `subject.` oder `resource.` bestimmt. Attributnamen dürfen nur ASCII-Buchstaben,
Ziffern, `_` und `-` enthalten. Werte werden wie folgt gespeichert:

| Quellwert | Map-Darstellung |
| --- | --- |
| Zahl | `u64` |
| `true` / `false` | `1` / `0` |
| String | stabiler `AttributeHash` |

Stringattribute unterstützen nur den Operator `==`. Zahlen und Booleans können mit `<`, `<=`,
`==`, `>=` und `>` verglichen werden. Namen und Stringwerte werden im Userspace gehasht, damit der
LSM-Hook nur feste numerische Werte vergleichen muss.

### 8. Kernelgeeignete Policy-Strukturen erzeugen

Nach erfolgreicher Validierung entstehen `FileOpenStaticPolicy` oder `FileOpenStreamPolicy`. Diese
gemeinsamen Typen verwenden `#[repr(C)]`, feste Arrays und skalare Werte. Sie enthalten keine
Userspace-Pointer, `String` oder `Vec` und können deshalb als Werte in Aya-/BPF-Maps übertragen
werden [[P8]](../tails-pdp-common/src/lib.rs).

`TranslatedPolicies` hält bis zum Commit zwei getrennte Vektoren:

```text
file_open_static
file_open_stream
```

Bis zu diesem Punkt ist keine neue Policy im Kernel aktiv.

### 9. Inaktive Policy-Bank vollständig schreiben

Jede Policy-Map enthält zwei Bänke mit jeweils 16 Einträgen:

```text
Index  0..15 = Bank 0
Index 16..31 = Bank 1
```

Die aktive Bank ergibt sich aus:

```text
(POLICY_GENERATION % 2) * 16
```

`PinnedPolicyMaps::commit` liest die aktuelle Generation, erhöht sie mit `wrapping_add(1)` und
berechnet daraus die momentan inaktive Bank. `write_bank` schreibt zunächst alle neuen Static- und
Stream-Policies in diese Bank. Nicht verwendete Slots werden explizit mit `disabled()`
überschrieben, damit keine Einträge einer älteren Generation zurückbleiben.

Während dieses Schreibvorgangs lesen eBPF und Userspace-PEP weiterhin ausschließlich die alte,
aktive Bank.

### 10. Generation atomar aktivieren

Erst nachdem beide Policy-Maps vollständig geschrieben wurden, setzt der Loader:

```text
POLICY_GENERATION[0] = nächste Generation
```

Diese einzelne Map-Aktualisierung ist der logische Commit-Punkt. Schlägt ein früherer Schreibzugriff
fehl, bleibt die alte Generation aktiv. Eine teilweise beschriebene inaktive Bank wird niemals über
die Generation ausgewählt.

Die statische eBPF-Stufe liest die aktive Generation zu Beginn eines `file_open`-Durchlaufs und
speichert sie im per-CPU `DecisionState`. Die nachfolgende Stream-Stufe verwendet genau diese
gespeicherte Generation. Ein paralleler Policy-Reload kann daher innerhalb eines Hook-Durchlaufs
keine alte Static-Bank mit einer neuen Stream-Bank vermischen.

### 11. Laufzeitänderungen und Rollback

Nach dem initialen Start beobachtet `PolicyDirectorySync::run` das Policyverzeichnis rekursiv über
Inotify. Nach einem Ereignis wartet der Loader 100 Millisekunden, um zusammengehörige
Dateisystemänderungen zu bündeln, und liest anschließend den vollständigen Verzeichnisstand neu.

Das Fehlerverhalten unterscheidet bewusst zwischen Start und Laufzeit:

| Zeitpunkt | Ungültige Policy-Konfiguration |
| --- | --- |
| initialer Start | Start wird vor dem Attach des LSM-Hooks abgebrochen |
| laufender Betrieb | Fehler wird geloggt, letzte gültige Generation bleibt aktiv |

Eine spätere korrigierte Datei erzeugt einen neuen Dokumentstand und wird erneut geparst,
validiert und über die inaktive Bank aktiviert.

### 12. Grenzen des aktuellen Parsers

Der Loader implementiert eine projektspezifische, zeilenbasierte SAPL-Teilmenge und keinen
vollständigen SAPL-Sprachparser. Insbesondere gilt:

- ein Statement muss vollständig in einer Zeile stehen,
- jedes Statement muss mit `;` enden,
- nur die explizit unterstützten Statements werden akzeptiert,
- Inline-Kommentare werden nicht entfernt,
- Escape-Sequenzen in Strings werden nicht gesondert interpretiert,
- `socket_bind` wird erkannt, aber beim Übersetzen abgelehnt,
- UTC-Stunden, -Minuten und -Sekunden werden als `u64` geparst, aber derzeit nicht auf ihre
  Kalenderbereiche begrenzt,
- Modulo `0` wird geparst; die Bedingung ist bei der Auswertung anschließend nicht anwendbar.

Diese Grenzen sollten bei einer Erweiterung der Policy-Sprache entweder bewusst beibehalten und
dokumentiert oder durch eine eigene Lexer-/Parser-Schicht ersetzt werden.

## Entscheidungen

Die Entscheidung wird durch `Entitlement` dargestellt:

```rust
pub enum Entitlement {
    Permit = 0,
    Deny = 1,
}
```

`Deny` bedeutet: Die Aktion soll verboten werden. `Permit` bedeutet: Die Policy spricht für
Erlauben. Aktuell überschreibt `Permit` ein `Deny` im Combine-Schritt aber nicht.

Die Zwischenentscheidung ist `DecisionState`:

| Feld | Bedeutung |
| --- | --- |
| `deny` | Es wurde mindestens eine Deny-Policy gefunden. |
| `permit` | Es wurde mindestens eine Permit-Policy gefunden. |
| `generation` | Policy-Generation, zu der die Entscheidung gehört. |

## Applicability

Eine Policy ist nur anwendbar, wenn alle relevanten Felder passen.

Beispiel `file_open` Static:

1. `enabled != 0`
2. `action == FileOpen`
3. UID passt oder Policy nutzt `ANY_SUBJECT`
4. Kommando passt oder Policy-Kommando ist leer
5. `device + inode` passen oder Policy-Ressource ist leer

Wenn eine Bedingung nicht passt, gibt die Funktion `None` zurück. Das heißt: Diese Policy trifft
keine Aussage.

## Stream Policies

Stream Policies enthalten eine Bedingung gegen einen dynamischen Wert. Aktuell sind Zeitwerte sowie
strukturierte Attribute aus `attributes/` unterstützt [[P8]](../tails-pdp-common/src/lib.rs), [[P23]](../tails-pdp-attribute-loader/src/stream_attributes.rs).

Unterstützte Attribute:

| Attribut | Bedeutung |
| --- | --- |
| `Time` | `current_time % modulo` |
| `Hour` | UTC-Stunde |
| `Minute` | UTC-Minute |
| `Second` | UTC-Sekunde |
| `system.<name>` | Globales Attribut aus `attributes/system.attributes`, gespeichert in `ATTRIBUTES`. |
| `subject.<name>` | Subjektattribut aus `attributes/subjects/<uid>.attributes`, gespeichert in `ATTRIBUTES`. |
| `resource.<name>` | Dateibezogenes Ressourcenattribut aus `attributes/resources/<pfad>.attributes`, gespeichert in `ATTRIBUTES`. |

Wichtig: Eine Stream Policy trifft nur dann eine Entscheidung, wenn die Stream-Bedingung wahr ist.
Ist die Bedingung falsch, ist die Policy nicht anwendbar [[P8]](../tails-pdp-common/src/lib.rs).

Freie Attributnamen und Stringwerte werden im Userspace stabil gehasht. Der eBPF-Code vergleicht
dadurch nur kleine feste Werte und muss keine Strings parsen. Pro Policy sind maximal vier
strukturierte Attributbedingungen vorgesehen.

## Wichtige Konstanten

| Konstante | Wert | Bedeutung |
| --- | --- | --- |
| `COMMAND_LEN` | `16` | Maximale Länge des Kommandonamens. |
| `RESOURCE_LEN` | `64` | Maximale Länge des Ressourcenstrings in der Policy. |
| `SOCKET_IP_LEN` | `16` | Platz für IPv4 oder IPv6. |
| `ANY_SUBJECT` | `u32::MAX` | Wildcard für beliebige UID. |
| `MAX_POLICIES` | `16` | Anzahl logischer Policies pro Map und Generation. |
| `POLICY_BANK_COUNT` | `2` | Zwei Bänke für atomare Generationenwechsel. |
| `POLICY_MAP_MAX_ENTRIES` | `32` | Zwei Bänke mal 16 Policies. |
| `DEFCON_MIN_LEVEL` | `1` | Kleinster gültiger DEFCON-Wert. |
| `DEFCON_MAX_LEVEL` | `5` | Größter gültiger DEFCON-Wert. |

## File-Open-Policies

### `FileOpenStaticPolicy`

Wichtige Felder:

| Feld | Bedeutung |
| --- | --- |
| `entitlement` | Permit oder Deny. |
| `action` | Muss `FileOpen` sein. |
| `enabled` | `1` aktiv, `0` deaktiviert. |
| `subject` | UID oder `ANY_SUBJECT`. |
| `command` | Prozessname, z. B. `cat`. |
| `resource` | Ursprünglicher Pfad als Byte-Array. |
| `resource_device` | Kernel-Device-ID der Datei. |
| `resource_inode` | Inode der Datei. |

Der Pfad wird im Userspace in `resolve_resource_identity` aufgelöst. Die Kernel-Auswertung nutzt
danach nur `device + inode`.

### `FileOpenStreamPolicy`

Zusätzlich zu Subject und Dateiressource enthält sie:

| Feld | Bedeutung |
| --- | --- |
| `attribute` | Stream-Attribut, z. B. `Hour` oder `Defcon`. |
| `operator` | Vergleichsoperator. |
| `modulo` | Nur bei `Time` relevant. |
| `value` | Vergleichswert. |
| `attribute_conditions` | Bis zu vier freie `system.*`-, `subject.*`- oder `resource.*`-Bedingungen. |

Stream-File-Policies verwenden wie Static Policies auch `subject`, `command` und die Dateiidentität
als statische Anwendbarkeitsfilter.

## Socket-Bind-Policies

Die gemeinsamen Datentypen für `socket_bind` sind vorhanden. Der aktuelle Dateiloader lehnt
`socket_bind`-Policies jedoch bewusst ab, und es wird kein Socket-LSM-Hook angehängt. Die folgenden
Strukturen beschreiben daher vorbereitete, derzeit nicht produktiv aktivierte Typen.

### `SocketBindStaticPolicy`

Wichtige Felder:

| Feld | Bedeutung |
| --- | --- |
| `socket_family` | `Any`, `Inet` oder `Inet6`. |
| `socket_transport` | `Any`, `Tcp` oder `Udp`. |
| `socket_port` | Lokaler Port, `0` als Wildcard. |
| `resource` | IP als Text. |
| `socket_ip` | IP als Byte-Array. |

`0.0.0.0` und `::` werden als Byte-Arrays mit Nullen gespeichert und matchen dadurch als Wildcard.

### `SocketBindStreamPolicy`

Wie Static, zusätzlich mit Stream-Bedingung.

## Warum feste Byte-Arrays?

eBPF-Code kann keine normalen Rust-Strings wie im Userspace verwenden. Außerdem müssen Structs in
Maps eine feste Größe haben. Deshalb verwendet das Projekt feste Byte-Arrays:

- `[u8; COMMAND_LEN]`
- `[u8; RESOURCE_LEN]`
- `[u8; SOCKET_IP_LEN]`

Ein String ist dabei bis zum ersten Nullbyte gültig. Das Admin-Tool rekonstruiert Strings in
[`tails-pdp-admintool/src/output.rs`](../tails-pdp-admintool/src/output.rs) mit der Hilfsfunktion `fixed_string`.

## `#[repr(C)]`

Viele Structs in `tails-pdp-common` nutzen `#[repr(C)]`. Das sorgt für eine C-kompatible
Speicheranordnung. Das ist wichtig, weil dieselben Structs in eBPF-Maps zwischen Userspace und
Kernel gelesen werden.

Wenn sich Felder ändern, ändern sich häufig auch Größe und Layout der Map-Werte. Dann müssen alte
gepinnte Maps entfernt werden [[P4]](../tails-pdp-policy-loader/src/policy_loader.rs), [[P12]](../tails-pdp-ebpf/src/maps.rs), [Q5], [Q23].

---

**Previous:** [Userspace-Komponenten](05-userspace-komponenten.md) | **Next:** [Fehlerbehandlung und Sicherheit](07-fehlerbehandlung-und-sicherheit.md)

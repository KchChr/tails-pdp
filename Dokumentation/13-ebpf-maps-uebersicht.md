# eBPF-Maps: vollständige Übersicht

Diese Übersicht beschreibt den aktuellen Stand der eBPF-Maps im Prototyp. Die Definitionen stehen in
[`tails-pdp-ebpf/src/maps.rs`](../tails-pdp-ebpf/src/maps.rs). Gemeinsame Datentypen und Konstanten
stehen in [`tails-pdp-common/src/lib.rs`](../tails-pdp-common/src/lib.rs).

Der Pin-Pfad für gepinnte Maps ist:

```text
/sys/fs/bpf/tails-pdp/<MAP_NAME>
```

Nicht gepinnte Maps existieren nur innerhalb des geladenen eBPF-Objekts und werden nicht über das
BPF-Dateisystem für andere Prozesse geöffnet.

## Gesamtübersicht

| Map | eBPF-Typ | Key-Typ | Value-Typ | Einträge | Gepinnt | Zweck |
| --- | --- | --- | --- | ---: | --- | --- |
| `FILE_OPEN_JUMP_TABLE` | `ProgramArray` | `u32` | Programm-FD | 3 | Nein | Tail-Call-Ziele für die `file_open`-Auswertung. |
| `DECISIONS` | `PerCpuArray` | `u32` | `u32` | 3 | Nein | Temporärer Entscheidungszustand innerhalb einer Tail-Call-Kette. |
| `DEBUG_LOGGING` | `Array` | `u32` | `u32` | 1 | Nein | Aktiviert oder deaktiviert eBPF-Debug-Ausgaben. |
| `POLICY_GENERATION` | `Array` | `u32` | `u32` | 1 | Ja | Aktive Policy-Generation. |
| `FILE_OPEN_STATIC_POLICIES` | `Array` | `u32` | `FileOpenStaticPolicy` | 32 | Ja | Statische `file_open`-Policies in zwei Bänken. |
| `FILE_OPEN_STREAM_POLICIES` | `Array` | `u32` | `FileOpenStreamPolicy` | 32 | Ja | Streambasierte `file_open`-Policies in zwei Bänken. |
| `CURRENT_TIME` | `Array` | `u32` | `u64` | 1 | Ja | Gemeinsame Unix-Zeitbasis für Kernel- und Userspace-PEP. |
| `ATTRIBUTE_GENERATION` | `Array` | `u32` | `u32` | 1 | Ja | Aktive Attributgeneration. |
| `ATTRIBUTES` | `HashMap` | `AttributeKey` | `AttributeValue` | 1024 | Ja | System-, Subjekt- und Ressourcenattribute. |

Hinweis: Die Policy-Maps haben 32 Einträge, weil `POLICY_BANK_COUNT = 2` und
`POLICY_BANK_SIZE = MAX_POLICIES = 16` gilt. Pro Generation sind dadurch 16 statische und
16 streambasierte `file_open`-Policies vorgesehen.

## Gemeinsame Konstanten

| Konstante | Wert | Bedeutung |
| --- | ---: | --- |
| `COMMAND_LEN` | 16 | Feste Länge für den Prozessnamen in Policy-Einträgen. |
| `RESOURCE_LEN` | 64 | Feste Länge für den Ressourcenpfad in Policy-Einträgen vor der Auflösung. |
| `MAX_POLICIES` | 16 | Anzahl Policies pro Bank und Policy-Typ. |
| `POLICY_BANK_COUNT` | 2 | Anzahl Policy-Bänke. |
| `POLICY_BANK_SIZE` | 16 | Anzahl Einträge pro Policy-Bank. |
| `POLICY_MAP_MAX_ENTRIES` | 32 | Gesamteinträge je Policy-Map. |
| `ATTRIBUTE_BANK_COUNT` | 2 | Anzahl Attribut-Bänke. |
| `ATTRIBUTE_MAP_MAX_ENTRIES` | 1024 | Maximale Anzahl Attribut-Einträge in `ATTRIBUTES`. |
| `MAX_ATTRIBUTE_CONDITIONS` | 4 | Maximale Anzahl dynamischer Attributbedingungen pro Stream-Policy. |

Die aktive Policy-Bank wird aus der Generation berechnet:

```rust
policy_bank_offset(generation) =
    (generation % POLICY_BANK_COUNT) * POLICY_BANK_SIZE
```

Die aktive Attribut-Bank wird entsprechend berechnet:

```rust
attribute_bank(generation) =
    generation % ATTRIBUTE_BANK_COUNT
```

## `FILE_OPEN_JUMP_TABLE`

Definition:

```rust
ProgramArray::with_max_entries(3, 0)
```

| Eigenschaft | Wert |
| --- | --- |
| Map-Typ | `ProgramArray` |
| Key-Typ | `u32` |
| Value | eBPF-Programm-FD |
| Einträge | 3 |
| Gepinnt | Nein |

Slots:

| Index | Zielprogramm |
| ---: | --- |
| 0 | `evaluate_file_open_static_policies` |
| 1 | `evaluate_file_open_stream_policies` |
| 2 | `combine_file_open` |

Einsatz:

| Komponente | Verwendung |
| --- | --- |
| [`tails-pdp/src/main.rs`](../tails-pdp/src/main.rs) | Öffnet die Map und setzt die Programm-FDs in die Tail-Call-Slots. |
| [`tails-pdp-ebpf/src/hooks.rs`](../tails-pdp-ebpf/src/hooks.rs) | Springt vom `file_open`-Hook in Slot 0. |
| [`tails-pdp-ebpf/src/policies/file_open_static_policies.rs`](../tails-pdp-ebpf/src/policies/file_open_static_policies.rs) | Springt nach statischer Auswertung in Slot 1. |
| [`tails-pdp-ebpf/src/policies/file_open_stream_policies.rs`](../tails-pdp-ebpf/src/policies/file_open_stream_policies.rs) | Springt nach Stream-Auswertung in Slot 2. |

Funktion:

Die Map zerlegt die `file_open`-Auswertung in mehrere kleinere eBPF-Programme. Dadurch bleiben die
einzelnen Programme für den Verifier einfacher analysierbar.

## `DECISIONS`

Definition:

```rust
PerCpuArray::<u32>::with_max_entries(3, 0)
```

| Eigenschaft | Wert |
| --- | --- |
| Map-Typ | `PerCpuArray` |
| Key-Typ | `u32` |
| Value-Typ | `u32` |
| Einträge | 3 |
| Gepinnt | Nein |

Indizes:

| Index | Bedeutung |
| ---: | --- |
| 0 | `deny` wurde in der aktuellen Tail-Call-Kette gesehen. |
| 1 | `permit` wurde in der aktuellen Tail-Call-Kette gesehen. |
| 2 | Policy-Generation der aktuellen Entscheidung. |

Einsatz:

| Komponente | Verwendung |
| --- | --- |
| [`tails-pdp-ebpf/src/policies/file_open_static_policies.rs`](../tails-pdp-ebpf/src/policies/file_open_static_policies.rs) | Schreibt den ersten Entscheidungszustand nach statischer Auswertung. |
| [`tails-pdp-ebpf/src/policies/file_open_stream_policies.rs`](../tails-pdp-ebpf/src/policies/file_open_stream_policies.rs) | Liest den vorhandenen Zustand, ergänzt Stream-Ergebnisse und schreibt zurück. |
| [`tails-pdp-ebpf/src/policies/combine.rs`](../tails-pdp-ebpf/src/policies/combine.rs) | Liest den Zustand und erzeugt die finale Hook-Entscheidung. |

Funktion:

`DECISIONS` ist ein kurzlebiger Zwischenspeicher innerhalb einer Tail-Call-Kette. Die Map ist
`PerCpuArray`, damit parallele Hook-Ausführungen auf unterschiedlichen CPUs nicht denselben
Entscheidungszustand überschreiben.

## `DEBUG_LOGGING`

Definition:

```rust
Array::<u32>::with_max_entries(1, 0)
```

| Eigenschaft | Wert |
| --- | --- |
| Map-Typ | `Array` |
| Key-Typ | `u32` |
| Value-Typ | `u32` |
| Einträge | 1 |
| Gepinnt | Nein |

Einsatz:

| Komponente | Verwendung |
| --- | --- |
| [`tails-pdp/src/main.rs`](../tails-pdp/src/main.rs) | Schreibt `DEBUG_LOGGING[0]` abhängig von `TAILS_PDP_EBPF_DEBUG`. |
| [`tails-pdp-ebpf/src/logging.rs`](../tails-pdp-ebpf/src/logging.rs) | Liest `DEBUG_LOGGING[0]`, bevor eBPF-Debug-Ausgaben geschrieben werden. |

Funktion:

Die Map schaltet eBPF-Debug-Ausgaben zur Laufzeit an oder aus. `0` bedeutet aus, jeder andere Wert
bedeutet an.

## `POLICY_GENERATION`

Definition:

```rust
Array::<u32>::pinned(POLICY_GENERATION_MAX_ENTRIES, 0)
```

| Eigenschaft | Wert |
| --- | --- |
| Map-Typ | `Array` |
| Key-Typ | `u32` |
| Value-Typ | `u32` |
| Einträge | 1 |
| Gepinnt | Ja |
| Pin-Pfad | `/sys/fs/bpf/tails-pdp/POLICY_GENERATION` |

Einsatz:

| Komponente | Verwendung |
| --- | --- |
| [`tails-pdp-policy-loader/src/policy_source.rs`](../tails-pdp-policy-loader/src/policy_source.rs) | Liest aktuelle Generation, schreibt nach erfolgreichem Policy-Commit die nächste Generation. |
| [`tails-pdp-ebpf/src/policies/decision.rs`](../tails-pdp-ebpf/src/policies/decision.rs) | Liest die aktive Generation für die Kernel-Auswertung. |
| [`tails-pdp-userspace-pep/src/pep.rs`](../tails-pdp-userspace-pep/src/pep.rs) | Liest die aktive Generation für die Userspace-Nachbewertung. |
| [`tails-pdp-admintool/src/lib.rs`](../tails-pdp-admintool/src/lib.rs) | Zeigt Generation und aktive Policy-Bank an. |
| [`tails-pdp-policy-loader/src/policy_loader.rs`](../tails-pdp-policy-loader/src/policy_loader.rs) | Prüft beim Start das gepinnte Map-Layout. |

Funktion:

`POLICY_GENERATION[0]` entscheidet, welche Bank in den Policy-Maps aktiv ist. Neue Policies werden
zuerst in die inaktive Bank geschrieben. Erst danach wird `POLICY_GENERATION[0]` erhöht.

## `FILE_OPEN_STATIC_POLICIES`

Definition:

```rust
Array::<FileOpenStaticPolicy>::pinned(FILE_OPEN_STATIC_POLICY_MAX_ENTRIES, 0)
```

| Eigenschaft | Wert |
| --- | --- |
| Map-Typ | `Array` |
| Key-Typ | `u32` |
| Value-Typ | `FileOpenStaticPolicy` |
| Einträge | 32 |
| Gepinnt | Ja |
| Pin-Pfad | `/sys/fs/bpf/tails-pdp/FILE_OPEN_STATIC_POLICIES` |

Value-Struktur:

```rust
#[repr(C)]
pub struct FileOpenStaticPolicy {
    pub entitlement: Entitlement,
    pub action: PolicyAction,
    pub enabled: u8,
    pub _pad: u8,
    pub subject: u32,
    pub command: [u8; COMMAND_LEN],
    pub resource: [u8; RESOURCE_LEN],
    pub resource_device: u64,
    pub resource_inode: u64,
}
```

Einsatz:

| Komponente | Verwendung |
| --- | --- |
| [`tails-pdp-policy-loader/src/policy_source.rs`](../tails-pdp-policy-loader/src/policy_source.rs) | Schreibt statische `file_open`-Policies in die inaktive Bank. |
| [`tails-pdp-ebpf/src/policies/file_open_static_policies.rs`](../tails-pdp-ebpf/src/policies/file_open_static_policies.rs) | Liest aktive Bank und wertet statische Policies im LSM-Hook aus. |
| [`tails-pdp-userspace-pep/src/pep.rs`](../tails-pdp-userspace-pep/src/pep.rs) | Liest aktive Bank und bewertet bestehende File Descriptors nachträglich. |
| [`tails-pdp-admintool/src/output.rs`](../tails-pdp-admintool/src/output.rs) | Gibt geladene statische Policies aus. |
| [`tails-pdp-policy-loader/src/policy_loader.rs`](../tails-pdp-policy-loader/src/policy_loader.rs) | Prüft beim Start das gepinnte Map-Layout. |

Funktion:

Die Map enthält Policies ohne dynamische Stream-Bedingungen. Der Userspace löst `resource.path` beim
Laden in `resource_device` und `resource_inode` auf. Im Kernel wird dann nicht der Pfad, sondern die
Dateiidentität verglichen.

Banklayout:

```text
Index 0..15   = Bank 0
Index 16..31  = Bank 1
```

## `FILE_OPEN_STREAM_POLICIES`

Definition:

```rust
Array::<FileOpenStreamPolicy>::pinned(FILE_OPEN_STREAM_POLICY_MAX_ENTRIES, 0)
```

| Eigenschaft | Wert |
| --- | --- |
| Map-Typ | `Array` |
| Key-Typ | `u32` |
| Value-Typ | `FileOpenStreamPolicy` |
| Einträge | 32 |
| Gepinnt | Ja |
| Pin-Pfad | `/sys/fs/bpf/tails-pdp/FILE_OPEN_STREAM_POLICIES` |

Value-Struktur:

```rust
#[repr(C)]
pub struct FileOpenStreamPolicy {
    pub entitlement: Entitlement,
    pub action: PolicyAction,
    pub attribute: StreamAttribute,
    pub operator: StreamOperator,
    pub enabled: u8,
    pub stream_condition_enabled: u8,
    pub attribute_condition_count: u8,
    pub _pad: u8,
    pub subject: u32,
    pub command: [u8; COMMAND_LEN],
    pub resource: [u8; RESOURCE_LEN],
    pub resource_device: u64,
    pub resource_inode: u64,
    pub modulo: u64,
    pub value: u64,
    pub attribute_conditions: [AttributeCondition; MAX_ATTRIBUTE_CONDITIONS],
}
```

Einsatz:

| Komponente | Verwendung |
| --- | --- |
| [`tails-pdp-policy-loader/src/policy_source.rs`](../tails-pdp-policy-loader/src/policy_source.rs) | Schreibt streambasierte `file_open`-Policies in die inaktive Bank. |
| [`tails-pdp-ebpf/src/policies/file_open_stream_policies.rs`](../tails-pdp-ebpf/src/policies/file_open_stream_policies.rs) | Liest aktive Bank, Zeit-Maps und Attribut-Map für die Stream-Auswertung. |
| [`tails-pdp-userspace-pep/src/pep.rs`](../tails-pdp-userspace-pep/src/pep.rs) | Liest aktive Bank und bewertet bestehende File Descriptors nachträglich gegen Stream-Policies. |
| [`tails-pdp-admintool/src/output.rs`](../tails-pdp-admintool/src/output.rs) | Gibt geladene Stream-Policies und Attributbedingungen aus. |
| [`tails-pdp-policy-loader/src/policy_loader.rs`](../tails-pdp-policy-loader/src/policy_loader.rs) | Prüft beim Start das gepinnte Map-Layout. |

Funktion:

Die Map enthält Policies mit Zeitbedingungen oder dynamischen Attributbedingungen. Statische Filter
wie Subjekt, Prozessname und Dateiidentität bleiben auch bei Stream-Policies erhalten. Zusätzlich
können eingebaute Zeitbedingungen und bis zu vier dynamische Attributbedingungen geprüft werden.

Banklayout:

```text
Index 0..15   = Bank 0
Index 16..31  = Bank 1
```

## `CURRENT_TIME`

Definition:

```rust
Array::<u64>::pinned(1, 0)
```

| Eigenschaft | Wert |
| --- | --- |
| Map-Typ | `Array` |
| Key-Typ | `u32` |
| Value-Typ | `u64` |
| Einträge | 1 |
| Gepinnt | Ja |
| Pin-Pfad | `/sys/fs/bpf/tails-pdp/CURRENT_TIME` |

Einsatz:

| Komponente | Verwendung |
| --- | --- |
| [`tails-pdp-attribute-loader/src/time.rs`](../tails-pdp-attribute-loader/src/time.rs) | Schreibt regelmäßig die aktuelle Unix-Zeit in Sekunden. |
| [`tails-pdp-ebpf/src/policies/file_open_stream_policies.rs`](../tails-pdp-ebpf/src/policies/file_open_stream_policies.rs) | Liest die Zeit für modulo- und UTC-komponentenbasierte Bedingungen. |
| [`tails-pdp-userspace-pep/src/pep.rs`](../tails-pdp-userspace-pep/src/pep.rs) | Liest dieselbe Zeitbasis für die Userspace-Auswertung. |
| [`tails-pdp-common/src/lib.rs`](../tails-pdp-common/src/lib.rs) | Leitet mit `PolicyTime::from_unix_seconds` UTC-Stunde, -Minute und -Sekunde ab. |
| [`tails-pdp-policy-loader/src/policy_loader.rs`](../tails-pdp-policy-loader/src/policy_loader.rs) | Prüft beim Start das gepinnte Map-Layout. |

Funktion:

Die Map stellt beiden PEPs dieselbe aktuelle Zeitbasis bereit. Die Konvertierung in UTC-Stunde,
-Minute und -Sekunde liegt in `tails-pdp-common`; Kernel und Userspace verwenden daher nicht zwei
unabhängige Implementierungen oder unterschiedlich aktualisierte Maps.

## `ATTRIBUTE_GENERATION`

Definition:

```rust
Array::<u32>::pinned(ATTRIBUTE_GENERATION_MAX_ENTRIES, 0)
```

| Eigenschaft | Wert |
| --- | --- |
| Map-Typ | `Array` |
| Key-Typ | `u32` |
| Value-Typ | `u32` |
| Einträge | 1 |
| Gepinnt | Ja |
| Pin-Pfad | `/sys/fs/bpf/tails-pdp/ATTRIBUTE_GENERATION` |

Einsatz:

| Komponente | Verwendung |
| --- | --- |
| [`tails-pdp-attribute-loader/src/stream_attributes.rs`](../tails-pdp-attribute-loader/src/stream_attributes.rs) | Erhöht die Generation nach erfolgreichem Schreiben einer Attribut-Bank. |
| [`tails-pdp-ebpf/src/policies/file_open_stream_policies.rs`](../tails-pdp-ebpf/src/policies/file_open_stream_policies.rs) | Liest die aktive Attribut-Bank. |
| [`tails-pdp-userspace-pep/src/pep.rs`](../tails-pdp-userspace-pep/src/pep.rs) | Liest die aktive Attribut-Bank für die Nachbewertung bestehender FDs. |
| [`tails-pdp-admintool/src/lib.rs`](../tails-pdp-admintool/src/lib.rs) | Zeigt aktive Attributgeneration und aktive Bank an. |
| [`tails-pdp-policy-loader/src/policy_loader.rs`](../tails-pdp-policy-loader/src/policy_loader.rs) | Prüft beim Start das gepinnte Map-Layout. |

Funktion:

`ATTRIBUTE_GENERATION[0]` bestimmt, welche Attribut-Bank in `ATTRIBUTES` aktiv ist. Neue Attribute
werden zuerst in die inaktive Bank geschrieben. Anschließend wird die Generation erhöht.

## `ATTRIBUTES`

Definition:

```rust
HashMap::<AttributeKey, AttributeValue>::pinned(ATTRIBUTE_MAP_MAX_ENTRIES, 0)
```

| Eigenschaft | Wert |
| --- | --- |
| Map-Typ | `HashMap` |
| Key-Typ | `AttributeKey` |
| Value-Typ | `AttributeValue` |
| Einträge | 1024 |
| Gepinnt | Ja |
| Pin-Pfad | `/sys/fs/bpf/tails-pdp/ATTRIBUTES` |

Key-Struktur:

```rust
#[repr(C)]
pub struct AttributeKey {
    pub bank: u32,
    pub namespace: u32,
    pub object_id_primary: u64,
    pub object_id_secondary: u64,
    pub name_hash: AttributeHash,
}
```

Value-Struktur:

```rust
#[repr(C)]
pub struct AttributeValue {
    pub kind: AttributeValueKind,
    pub _pad: [u8; 7],
    pub number: u64,
    pub hash: AttributeHash,
}
```

Hilfsstruktur für Namen und Stringwerte:

```rust
#[repr(C)]
pub struct AttributeHash {
    pub low: u64,
    pub high: u64,
}
```

Namespaces:

| Namespace | Objekt-ID |
| --- | --- |
| `System` | `(0, 0)` |
| `Subject` | `(uid, 0)` |
| `Resource` | `(device, inode)` |

Einsatz:

| Komponente | Verwendung |
| --- | --- |
| [`tails-pdp-attribute-loader/src/stream_attributes.rs`](../tails-pdp-attribute-loader/src/stream_attributes.rs) | Liest `attributes/` und schreibt Attributwerte in die inaktive Bank. |
| [`tails-pdp-ebpf/src/policies/file_open_stream_policies.rs`](../tails-pdp-ebpf/src/policies/file_open_stream_policies.rs) | Liest Attributwerte für dynamische Stream-Policy-Bedingungen. |
| [`tails-pdp-userspace-pep/src/pep.rs`](../tails-pdp-userspace-pep/src/pep.rs) | Liest Attributwerte für die Userspace-Nachbewertung bestehender FDs. |
| [`tails-pdp-admintool/src/output.rs`](../tails-pdp-admintool/src/output.rs) | Gibt Attribute aus und versucht Hashwerte über Policy- und Attributdateien lesbar zu machen. |
| [`tails-pdp-policy-loader/src/policy_loader.rs`](../tails-pdp-policy-loader/src/policy_loader.rs) | Prüft beim Start das gepinnte Map-Layout. |

Funktion:

`ATTRIBUTES` enthält dynamische System-, Subjekt- und Ressourcenattribute. Attributnamen und
Stringwerte werden nicht als Klartext in der Map gespeichert, sondern als `AttributeHash`.
Zahlenwerte und Boolean-Werte werden im Feld `number` abgelegt. Stringwerte werden im Feld `hash`
abgelegt.

Beispiele:

| Datei | Policy-Name | Map-Key |
| --- | --- | --- |
| `attributes/system.attributes` | `system.defcon` | `namespace=System`, Objekt `(0, 0)`, `name_hash=hash("defcon")` |
| `attributes/subjects/1000.attributes` | `subject.position` | `namespace=Subject`, Objekt `(1000, 0)`, `name_hash=hash("position")` |
| `attributes/resources/home/hntr/test.txt.attributes` | `resource.classification` | `namespace=Resource`, Objekt `(device, inode)`, `name_hash=hash("classification")` |

## Gepinnte Maps und Layout-Prüfung

Gepinnte Maps bleiben unter `/sys/fs/bpf/tails-pdp/` sichtbar und können von mehreren
Userspace-Komponenten geöffnet werden. Das ist notwendig für:

- Policy-Sync in [`tails-pdp-policy-loader/src/policy_source.rs`](../tails-pdp-policy-loader/src/policy_source.rs)
- Attribut-Sync in [`tails-pdp-attribute-loader/src/stream_attributes.rs`](../tails-pdp-attribute-loader/src/stream_attributes.rs)
- Userspace-PEP in [`tails-pdp-userspace-pep/src/pep.rs`](../tails-pdp-userspace-pep/src/pep.rs)
- Admin-Tool in [`tails-pdp-admintool/`](../tails-pdp-admintool/)

Vor dem Laden prüft [`tails-pdp-policy-loader/src/policy_loader.rs`](../tails-pdp-policy-loader/src/policy_loader.rs), ob bereits
gepinnte Maps mit kompatiblem Layout existieren. Geprüft werden:

- Key-Größe
- Value-Größe
- maximale Anzahl Einträge

Wenn ein Layout nicht passt, muss die alte gepinnte Map gelöscht und das Programm neu gestartet
werden.

## Nicht mehr vorhandene Socket-Maps

Ältere Dokumentationsstände erwähnten Socket-Bind-Maps. Im aktuellen eBPF-Code sind diese Maps nicht
definiert und nicht aktiv. Der aktuelle Prototyp betrachtet `file_open`.

---

**Previous:** [Quellen und Zitierweise](12-quellen.md) | **Next:** -

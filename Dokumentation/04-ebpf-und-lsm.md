# eBPF- und LSM-Teil

## Einstieg

Der eBPF-Code liegt im Crate `tails-pdp-ebpf`. Der eigentliche eBPF-Binary-Einstieg ist
[`tails-pdp-ebpf/src/main.rs`](../tails-pdp-ebpf/src/main.rs) [[P9]](../tails-pdp-ebpf/src/main.rs). Die allgemeinen Einschränkungen durch eBPF, BPF-Maps und den
Verifier sind in der Linux-Kernel-Dokumentation beschrieben [Q4], [Q5], [Q7], [Q8].

Wichtige Eigenschaften:

- `#![no_std]`: keine Rust-Standardbibliothek
- `#![no_main]`: kein normaler Programmstart wie bei Userspace-Binaries
- eigener Panic-Handler, der in einer Endlosschleife bleibt

Das ist typisch für eBPF-Programme.

## LSM-Programme

Die Einstiegshooks stehen in [`tails-pdp-ebpf/src/hooks.rs`](../tails-pdp-ebpf/src/hooks.rs):

| Funktion | Hook | Aufgabe |
| --- | --- | --- |
| `file_open` | `file_open` | Einstieg für Dateiöffnungen. |

Die Funktion tut nur wenig:

1. Den Rückgabewert eines vorherigen BPF-LSM-Programms prüfen und eine bestehende Ablehnung
   unverändert weitergeben.
2. UID lesen.
3. Optional debuggen.
4. Per Tail Call in die eigentliche Policy-Auswertung springen.
5. Falls der Tail Call fehlschlägt, mit `-EPERM` sicher ablehnen.

Der erfolgreiche Tail Call kehrt nicht zum aufrufenden eBPF-Programm zurück. Wird der Code danach
erreicht, ist die Enforcement-Kette unvollständig. Das Projekt behandelt diesen Infrastrukturfehler
deshalb bewusst fail-closed.

## Tail-Call-Ketten

### `file_open`

| Schritt | Funktion |
| --- | --- |
| 1 | `hooks.rs::file_open` |
| 2 | `file_open_static_policies.rs::evaluate_file_open_static_policies` |
| 3 | `file_open_stream_policies.rs::evaluate_file_open_stream_policies` |
| 4 | `combine.rs::combine_file_open` |

Warum so? Der eBPF-Verifier akzeptiert kleinere, klarere Programme eher als ein großes Programm mit
viel Logik [Q7], [Q8].

## Maps im eBPF-Teil

Die Maps stehen in [`tails-pdp-ebpf/src/maps.rs`](../tails-pdp-ebpf/src/maps.rs).

| Map | Typ | Zweck |
| --- | --- | --- |
| `FILE_OPEN_JUMP_TABLE` | `ProgramArray` | Tail Calls für `file_open`. |
| `DECISIONS` | `PerCpuArray<u32>` | Zwischenentscheidung pro CPU. |
| `DEBUG_LOGGING` | `Array<u32>` | Schaltet `bpf_printk!` zur Laufzeit an/aus. |
| `POLICY_GENERATION` | gepinnte `Array<u32>` | Aktive Policy-Generation. |
| `FILE_OPEN_STATIC_POLICIES` | gepinnte `Array<FileOpenStaticPolicy>` | Datei-Static-Policies. |
| `FILE_OPEN_STREAM_POLICIES` | gepinnte `Array<FileOpenStreamPolicy>` | Datei-Stream-Policies. |
| `CURRENT_TIME` | gepinnte `Array<u64>` | Aktuelle Unix-Zeit; UTC-Stunde, -Minute und -Sekunde werden daraus mit gemeinsamem Code abgeleitet. |
| `ATTRIBUTE_GENERATION` | gepinnte `Array<u32>` | Aktive Generation strukturierter Attribute. |
| `ATTRIBUTES` | gepinnte `HashMap<AttributeKey, AttributeValue>` | Strukturierte Attribute aus `attributes/system.attributes`, `attributes/subjects/<uid>.attributes` und `attributes/resources/<pfad>.attributes`. |

`DECISIONS` ist eine Per-CPU-Map. Das reduziert Race Conditions, wenn mehrere CPUs gleichzeitig
LSM-Hooks ausführen [[P12]](../tails-pdp-ebpf/src/maps.rs), [Q6].

Eine vollständige Übersicht mit Key- und Value-Typen, Pin-Pfaden, Einträgen und Einsatzorten steht
in [eBPF-Maps: vollständige Übersicht](13-ebpf-maps-uebersicht.md).

## Gelesene Kernel-Daten

Die Hilfsfunktionen stehen in [`tails-pdp-ebpf/src/helpers.rs`](../tails-pdp-ebpf/src/helpers.rs).

### Dateiressource

`read_file_open_resource` liest aus dem Kernel:

- `struct file`
- daraus `f_inode`
- daraus `i_sb`
- daraus `s_dev`
- daraus `i_ino`

Das Ergebnis ist:

```rust
FileOpenResource {
    device,
    inode,
}
```

Der vollständige Pfad wird im Kernel nicht gematcht. Stattdessen löst der Userspace-Loader den Pfad
beim Laden der Policy in `device + inode` auf.

## `unsafe`

Im eBPF-Code gibt es `unsafe`, weil Kernel-Pointer gelesen und Tail Calls ausgeführt werden.
Beispiele:

- `bpf_probe_read_kernel(...)` in [`tails-pdp-ebpf/src/helpers.rs`](../tails-pdp-ebpf/src/helpers.rs)
- `tail_call(...)` in [`tails-pdp-ebpf/src/hooks.rs`](../tails-pdp-ebpf/src/hooks.rs) und den Dateien unter [`tails-pdp-ebpf/src/policies/`](../tails-pdp-ebpf/src/policies/)
- Schreiben in `DECISIONS` über `get_ptr_mut` in [`tails-pdp-ebpf/src/policies/decision.rs`](../tails-pdp-ebpf/src/policies/decision.rs)

`unsafe` heißt nicht automatisch „falsch“. Es heißt: Der Compiler kann die Sicherheit nicht allein
prüfen. Deshalb muss der Code besonders defensiv sein.

Defensive Muster im Code:

- Null-Pointer prüfen
- `bpf_probe_read_kernel`-Fehler abfangen
- fehlgeschlagene Kernel-Lesezugriffe nicht mit der gültigen Wildcard-Ressource `(0, 0)` vermischen
- Map-Zugriffe mit `Option` behandeln
- bei fehlenden Decision-, Generations- oder Zeit-Map-Einträgen sicher ablehnen
- fehlgeschlagene Tail Calls sicher ablehnen
- begrenzte Schleifen über `POLICY_BANK_SIZE`

## Verifier-freundliche Muster

Der eBPF-Code vermeidet:

- dynamische Allokation
- Rekursion
- unbeschränkte Schleifen
- große lokale Objekte
- komplizierte String-Verarbeitung im Kernel

Stattdessen nutzt er:

- feste Structs mit `#[repr(C)]`
- feste Array-Längen
- Tail Calls
- klare `while index < POLICY_BANK_SIZE`-Schleifen
- einfache numerische Vergleiche

## Rückgabewerte

In LSM-eBPF gilt:

| Rückgabewert | Bedeutung |
| --- | --- |
| `0` | Aktion erlauben. |
| negativer Wert, hier `-1` | Aktion verweigern. |

`combine.rs::combine_decision` gibt aktuell `-1` zurück, sobald ein Deny gesehen wurde. Permit wird
gespeichert, überschreibt Deny aber aktuell nicht.

---

**Previous:** [Build, Start und Betrieb](03-build-start-und-betrieb.md) | **Next:** [Userspace-Komponenten](05-userspace-komponenten.md)

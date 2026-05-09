# eBPF- und LSM-Teil

## Einstieg

Der eBPF-Code liegt im Crate `tails-pdp-ebpf`. Der eigentliche eBPF-Binary-Einstieg ist
`tails-pdp-ebpf/src/main.rs`.

Wichtige Eigenschaften:

- `#![no_std]`: keine Rust-Standardbibliothek
- `#![no_main]`: kein normaler Programmstart wie bei Userspace-Binaries
- eigener Panic-Handler, der in einer Endlosschleife bleibt

Das ist typisch für eBPF-Programme.

## LSM-Programme

Die Einstiegshooks stehen in `tails-pdp-ebpf/src/hooks.rs`:

| Funktion | Hook | Aufgabe |
| --- | --- | --- |
| `file_open` | `file_open` | Einstieg für Dateiöffnungen. |
| `socket_bind` | `socket_bind` | Einstieg für lokale Socket-Binds. |

Beide Funktionen tun nur wenig:

1. UID lesen.
2. Optional debuggen.
3. Per Tail Call in die eigentliche Policy-Auswertung springen.
4. Falls der Tail Call fehlschlägt, `0` zurückgeben.

`0` bedeutet: Kernel-Aktion erlauben.

## Tail-Call-Ketten

### `file_open`

| Schritt | Funktion |
| --- | --- |
| 1 | `hooks.rs::file_open` |
| 2 | `file_open_static_policies.rs::evaluate_file_open_static_policies` |
| 3 | `file_open_stream_policies.rs::evaluate_file_open_stream_policies` |
| 4 | `combine.rs::combine_file_open` |

### `socket_bind`

| Schritt | Funktion |
| --- | --- |
| 1 | `hooks.rs::socket_bind` |
| 2 | `socket_bind_static_policies.rs::evaluate_socket_bind_static_policies` |
| 3 | `socket_bind_stream_policies.rs::evaluate_socket_bind_stream_policies` |
| 4 | `combine.rs::combine_socket_bind` |

Warum so? Der eBPF-Verifier akzeptiert kleinere, klarere Programme eher als ein großes Programm mit
viel Logik.

## Maps im eBPF-Teil

Die Maps stehen in `tails-pdp-ebpf/src/maps.rs`.

| Map | Typ | Zweck |
| --- | --- | --- |
| `FILE_OPEN_JUMP_TABLE` | `ProgramArray` | Tail Calls für `file_open`. |
| `SOCKET_BIND_JUMP_TABLE` | `ProgramArray` | Tail Calls für `socket_bind`. |
| `DECISIONS` | `PerCpuArray<u32>` | Zwischenentscheidung pro CPU. |
| `DEBUG_LOGGING` | `Array<u32>` | Schaltet `bpf_printk!` zur Laufzeit an/aus. |
| `POLICY_GENERATION` | gepinnte `Array<u32>` | Aktive Policy-Generation. |
| `FILE_OPEN_STATIC_POLICIES` | gepinnte `Array<FileOpenStaticPolicy>` | Datei-Static-Policies. |
| `FILE_OPEN_STREAM_POLICIES` | gepinnte `Array<FileOpenStreamPolicy>` | Datei-Stream-Policies. |
| `SOCKET_BIND_STATIC_POLICIES` | gepinnte `Array<SocketBindStaticPolicy>` | Socket-Static-Policies. |
| `SOCKET_BIND_STREAM_POLICIES` | gepinnte `Array<SocketBindStreamPolicy>` | Socket-Stream-Policies. |
| `CURRENT_TIME` | gepinnte `Array<u64>` | Aktuelle Unix-Zeit. |
| `CURRENT_TIME_ISO8601` | gepinnte `Array<Iso8601TimeParts>` | Aktuelle UTC-Zeitfelder. |

`DECISIONS` ist eine Per-CPU-Map. Das reduziert Race Conditions, wenn mehrere CPUs gleichzeitig
LSM-Hooks ausführen.

## Gelesene Kernel-Daten

Die Hilfsfunktionen stehen in `tails-pdp-ebpf/src/helpers.rs`.

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

### Socketressource

`read_socket_bind_resource` liest:

- Socket-Familie: IPv4 oder IPv6
- Transporttyp: TCP oder UDP
- lokalen Port
- lokale IP-Adresse

Für IPv4 wird `sockaddr_in` gelesen, für IPv6 `sockaddr_in6`.

## `unsafe`

Im eBPF-Code gibt es `unsafe`, weil Kernel-Pointer gelesen und Tail Calls ausgeführt werden.
Beispiele:

- `bpf_probe_read_kernel(...)` in `helpers.rs`
- `tail_call(...)` in `hooks.rs` und Policy-Programmen
- Schreiben in `DECISIONS` über `get_ptr_mut` in `policies/decision.rs`

`unsafe` heißt nicht automatisch „falsch“. Es heißt: Der Compiler kann die Sicherheit nicht allein
prüfen. Deshalb muss der Code besonders defensiv sein.

Defensive Muster im Code:

- Null-Pointer prüfen
- `bpf_probe_read_kernel`-Fehler abfangen
- bei Fehlern leere Ressourcen zurückgeben
- Map-Zugriffe mit `Option` behandeln
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

## Quellen dieses Kapitels

Dieses Kapitel stützt sich auf die Projektquellen [P8], [P9], [P10], [P11], [P12], [P13], [P14],
[P15] und [P16] sowie auf die externen Quellen [Q5], [Q6], [Q7], [Q8], [Q9], [Q10] und [Q23]. Die
vollständige Quellenliste steht in [Quellen und Zitierweise](12-quellen.md).

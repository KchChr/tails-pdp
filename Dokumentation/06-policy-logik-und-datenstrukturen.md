# Policy-Logik und Datenstrukturen

## Gemeinsame Logik

Die zentrale Policy-Logik liegt in [`tails-pdp-common/src/lib.rs`](../tails-pdp-common/src/lib.rs). Dieses Crate wird von Userspace
und eBPF genutzt. Dadurch sollen beide Seiten dieselbe Entscheidung treffen [P8]. Die Policies
orientieren sich syntaktisch an einfachen SAPL-Policy-Dateien, werden aber in projektspezifische
Rust-Structs übersetzt [P3], [Q11].

Stream Policies bestehen weiterhin aus genau einer dynamischen Bedingung. Sie dürfen jetzt aber
zusätzlich die statischen Filter des jeweiligen Hooks mitbenutzen. Eine `file_open`-Stream-Policy
kann also `subject`, `command` und `resource.path` mit `environment.defcon.level` oder
`environment.utc.hour` kombinieren. Eine `socket_bind`-Stream-Policy kann entsprechend `subject`,
`command`, `resource.family`, `resource.transport`, `resource.ip` und `resource.port` mit einer
dynamischen Bedingung kombinieren [P3], [P8].

Wichtige Funktionen:

| Funktion | Zweck |
| --- | --- |
| `evaluate_file_open_static_policy` | Prüft eine Static Policy für Dateiöffnungen. |
| `evaluate_file_open_stream_policy` | Prüft eine Stream Policy für Dateiöffnungen. |
| `evaluate_socket_bind_static_policy` | Prüft eine Static Policy für Socket-Binds. |
| `evaluate_socket_bind_stream_policy` | Prüft eine Stream Policy für Socket-Binds. |
| `matches_stream_operator` | Vergleicht Werte mit `<`, `<=`, `==`, `>=`, `>`. |

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

Stream Policies enthalten eine Bedingung gegen einen dynamischen Wert. Aktuell sind Zeitwerte und
DEFCON sowie strukturierte Attribute aus `environment/` unterstützt [P8], [P23].

Unterstützte Attribute:

| Attribut | Bedeutung |
| --- | --- |
| `Time` | `current_time % modulo` |
| `Hour` | UTC-Stunde |
| `Minute` | UTC-Minute |
| `Second` | UTC-Sekunde |
| `Defcon` | Wert aus `CURRENT_DEFCON`, gespeist aus [`stream-attributes/DEFCON.txt`](../environment/DEFCON.txt) |
| `system.<name>` | Globales Attribut aus `environment/system.env`, gespeichert in `ATTRIBUTES`. |
| `subject.<name>` | Subjektattribut aus `environment/subjects/<uid>.env`, gespeichert in `ATTRIBUTES`. |
| `resource.<name>` | Dateibezogenes Ressourcenattribut aus `environment/resources/<pfad>.env`, gespeichert in `ATTRIBUTES`. |

Wichtig: Eine Stream Policy trifft nur dann eine Entscheidung, wenn die Stream-Bedingung wahr ist.
Ist die Bedingung falsch, ist die Policy nicht anwendbar [P8].

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
| `attribute_conditions` | Bis zu vier freie `system.*`- oder `subject.*`-Bedingungen. |

Stream-File-Policies enthalten aktuell kein `command`-Feld in der Auswertung.

## Socket-Bind-Policies

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
gepinnte Maps entfernt werden [P4], [P12], [Q5], [Q23].

---

**Previous:** [Userspace-Komponenten](05-userspace-komponenten.md) | **Next:** [Fehlerbehandlung und Sicherheit](07-fehlerbehandlung-und-sicherheit.md)

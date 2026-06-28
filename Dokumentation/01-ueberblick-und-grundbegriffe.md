# Projektüberblick und Grundbegriffe

## Was macht `tails-pdp`?

`tails-pdp` kontrolliert bestimmte Aktionen von Linux-Prozessen anhand von Policies. Eine Policy ist
eine Regel wie:

```sapl
policy "deny cat on /home/hntr/test.txt for uid 1000"
deny
    action == "file_open";
    subject.uid == 1000;
    command == "cat";
    resource.path == "/home/hntr/test.txt";
```

Diese Regel bedeutet vereinfacht:

Ein Prozess mit UID `1000`, dessen Kommando `cat` heißt, darf die Datei
`/home/hntr/test.txt` nicht öffnen.

Aktuell wird eine Aktion unterstützt:

| Aktion | Linux-Kontext | Beispiel |
| --- | --- | --- |
| `file_open` | Öffnen einer Datei | `cat /home/hntr/test.txt` |

## Welches Problem löst das Projekt?

Normale Dateirechte sind oft grob. Sie sagen zum Beispiel, ob ein Benutzer eine Datei lesen darf.
`tails-pdp` versucht, feiner zu entscheiden:

- Welcher Benutzer handelt?
- Welches Programm handelt?
- Welche Ressource ist betroffen?
- Zu welcher Zeit passiert der Zugriff?
- Welcher DEFCON-Level ist aktuell aktiv?
- Gilt eine statische Policy oder eine zeitabhängige Stream-Policy?

Der Begriff PDP steht für Policy Decision Point. Das ist die Komponente, die eine Policy auswertet
und eine Entscheidung trifft. Die konkrete Auswertung liegt in `tails-pdp-common`, die Kernel-Hooks
in [`tails-pdp-ebpf/src/hooks.rs`](../tails-pdp-ebpf/src/hooks.rs), und die aktiven Policies werden über eBPF-Maps bereitgestellt
[P8], [P10], [P12]. Die Begriffe eBPF, Map und LSM orientieren sich an der Linux-Kernel-
Dokumentation [Q4], [Q5], [Q9], [Q10].

PEP steht für Policy Enforcement Point. Der eBPF-LSM-Hook ist der Kernelspace-PEP für neue
Dateiöffnungen. Der Userspace-PEP kontrolliert bereits bestehende Dateizugriffe nach Änderungen von
Policies oder Attributen erneut.

## Rust

Rust ist eine Programmiersprache mit starkem Fokus auf Speichersicherheit. Das bedeutet: Viele
Fehler wie ungültige Speicherzugriffe werden schon beim Kompilieren verhindert. Dieses Projekt nutzt
Rust sowohl im Userspace als auch für eBPF-Code.

Wichtig: eBPF-Rust ist eingeschränkter als normales Rust. Der eBPF-Teil nutzt `#![no_std]`, also
keine Standardbibliothek. Das ist nötig, weil eBPF-Code im Kernel-Kontext läuft.

## Userspace und Kernelspace

Linux trennt Programme in zwei Bereiche:

| Bereich | Bedeutung |
| --- | --- |
| Userspace | Normale Programme wie Shell, `cat`, der `tails-pdp`-Loader oder das Admin-Tool. |
| Kernelspace | Der Linux-Kernel. Er kontrolliert Hardware, Prozesse, Dateizugriffe und Netzwerk. |

Der Kernelspace ist sicherheitskritisch. Fehler dort können das ganze System betreffen. Deshalb ist
eBPF stark eingeschränkt und wird vor dem Laden geprüft.

## eBPF

eBPF ist eine Linux-Technik, mit der kleine Programme kontrolliert in den Kernel geladen werden
können. Sie können an bestimmte Ereignisse gehängt werden, zum Beispiel an Netzwerkereignisse oder
Security-Hooks.

In diesem Projekt liegen die eBPF-Programme im Crate `tails-pdp-ebpf`, vor allem in:

- [`tails-pdp-ebpf/src/hooks.rs`](../tails-pdp-ebpf/src/hooks.rs)
- [`tails-pdp-ebpf/src/policies/`](../tails-pdp-ebpf/src/policies/)
- [`tails-pdp-ebpf/src/helpers.rs`](../tails-pdp-ebpf/src/helpers.rs)
- [`tails-pdp-ebpf/src/maps.rs`](../tails-pdp-ebpf/src/maps.rs)

## Aya

Aya ist eine Rust-Bibliothek für eBPF. Sie hat zwei Seiten:

- `aya` im Userspace, um eBPF-Programme zu laden, Maps zu öffnen und Programme anzuhängen.
- `aya-ebpf` im Kernel-/eBPF-Teil, um Maps, LSM-Programme und Hilfsfunktionen zu definieren.

Konkrete Beispiele:

- [`tails-pdp/src/main.rs`](../tails-pdp/src/main.rs) nutzt `aya::EbpfLoader`.
- [`tails-pdp-ebpf/src/hooks.rs`](../tails-pdp-ebpf/src/hooks.rs) nutzt `#[lsm(hook = "...")]`.
- [`tails-pdp-ebpf/src/maps.rs`](../tails-pdp-ebpf/src/maps.rs) nutzt `#[map]`.

## Linux Security Modules

Linux Security Modules, kurz LSM, sind Schnittstellen im Linux-Kernel, an denen Sicherheitsprüfungen
eingehängt werden können. Bekannte Systeme wie SELinux oder AppArmor nutzen ebenfalls LSM-Konzepte.

Ein LSM-Hook ist ein konkreter Prüfpunkt im Kernel. Im Prototyp wird verwendet:

- `file_open`: wird aufgerufen, wenn eine Datei geöffnet werden soll.
Das eBPF-Programm ist an diesen Hook angebunden.

## Maps

Eine eBPF-Map ist ein Speicherbereich, den eBPF-Programme und Userspace-Programme gemeinsam nutzen
können. Man kann sie sich wie eine kleine Tabelle vorstellen.

Beispiele aus [`tails-pdp-ebpf/src/maps.rs`](../tails-pdp-ebpf/src/maps.rs):

| Map | Zweck |
| --- | --- |
| `FILE_OPEN_STATIC_POLICIES` | Static Policies für `file_open`. |
| `FILE_OPEN_STREAM_POLICIES` | Stream Policies für `file_open`. |
| `POLICY_GENERATION` | Aktive Policy-Generation. |
| `DECISIONS` | Zwischenentscheidung innerhalb einer Tail-Call-Kette. |
| `CURRENT_TIME` | Aktuelle Unix-Zeit für Stream-Policies. |
| `CURRENT_TIME_ISO8601` | Aktuelle UTC-Zeit in Feldern wie Stunde, Minute, Sekunde. |
| `ATTRIBUTES` | Strukturierte System-, Subjekt- und Ressourcenattribute, darunter `system.defcon`. |

Viele Maps sind gepinnt. Gepinnt bedeutet: Sie liegen unter `/sys/fs/bpf/tails-pdp/...` und können
auch von anderen Prozessen geöffnet werden [P12], [Q5], [Q23].

## Perf Events oder Ring Buffer

Dieses Projekt verwendet aktuell keinen Perf Event Buffer und keinen Ring Buffer für Events. Das ist
wichtig: Kernel-Events werden nicht als Eventstrom in den Userspace geschickt.

Stattdessen gibt es zwei andere Mechanismen:

- Debug-Ausgaben im Kernel über `bpf_printk!`, sichtbar über `trace_pipe`.
- Nachträgliche Kontrolle durch den Userspace-PEP über `/proc/<pid>/fd`.

## Verifier

Der eBPF-Verifier ist ein Kernel-Prüfer. Bevor ein eBPF-Programm geladen wird, analysiert der
Verifier, ob es sicher ist.

Er prüft unter anderem:

- Kann das Programm endlos laufen?
- Greift es nur auf erlaubten Speicher zu?
- Ist der Stack-Verbrauch begrenzt?
- Sind Pointer sicher?
- Sind Map-Zugriffe im gültigen Bereich?

Wenn der Verifier ein Problem sieht, wird das Programm nicht geladen. Typische Fehlermeldungen sind
`Permission denied`, `Invalid argument` oder irreführend auch `No space left on device`.

## Stack-Limit im eBPF-Kontext

Der Stack ist ein kleiner Speicherbereich für lokale Variablen einer Funktion. Im eBPF-Kontext ist
dieser Speicher sehr begrenzt. Rust-Code, der im Userspace harmlos wäre, kann im eBPF-Teil zu groß
werden.

Deshalb ist der eBPF-Code hier bewusst einfach aufgebaut:

- feste Arrays statt dynamischer Datenstrukturen
- kleine Structs
- begrenzte Schleifen
- defensive Map-Zugriffe
- Aufteilung über Tail Calls

---

**Previous:** [Dokumentation](Documentation.md) | **Next:** [Architektur und Datenfluss](02-architektur-und-datenfluss.md)

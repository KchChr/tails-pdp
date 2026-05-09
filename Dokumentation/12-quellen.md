# Quellen und Zitierweise

Diese Dokumentation nutzt zwei Arten von Quellen:

- **Projektquellen** `[P...]`: Dateien aus diesem Repository. Sie belegen, wie `tails-pdp`
  konkret implementiert ist.
- **Externe Quellen** `[Q...]`: Offizielle Dokumentation oder technische Referenzen. Sie belegen
  allgemeine Aussagen zu Rust, Aya, eBPF, Linux Security Modules, Linux-Interfaces und SAPL.

Die externen Quellen sind bevorzugt Primärquellen: Linux-Kernel-Dokumentation, Linux-Man-Pages,
Rust-Dokumentation, Aya-Dokumentation und SAPL-Dokumentation.

## Projektquellen

| ID | Quelle | Verwendet für |
| --- | --- | --- |
| [P1] | [`tails-pdp/src/main.rs`](../tails-pdp/src/main.rs) | Hauptprogramm, eBPF-Loader, LSM-Load/Attach, Tail-Call-Setup, Logging, Policy-Sync, Zeit-Update und Monitor-Start. |
| [P2] | [`tails-pdp/src/lib.rs`](../tails-pdp/src/lib.rs) | Userspace-Bibliothek und Modulstruktur. |
| [P3] | [`tails-pdp/src/policy_source.rs`](../tails-pdp/src/policy_source.rs) | Lesen, Parsen und Synchronisieren der `.sapl`-Policy-Dateien. |
| [P4] | [`tails-pdp/src/policy_loader.rs`](../tails-pdp/src/policy_loader.rs) | Schreiben kompilierter Policies in die eBPF-Maps. |
| [P5] | [`tails-pdp/src/time.rs`](../tails-pdp/src/time.rs) | Aktualisierung der Zeit-Maps `CURRENT_TIME` und `CURRENT_TIME_ISO8601`. |
| [P6] | [`tails-pdp/src/monitor.rs`](../tails-pdp/src/monitor.rs) | Userspace-Monitoring von Prozessen, Sockets und File Descriptors. |
| [P7] | [`tails-pdp/src/fd_revoker.rs`](../tails-pdp/src/fd_revoker.rs) | Schließen fremder File Descriptors per `ptrace` auf x86_64 Linux. |
| [P8] | [`tails-pdp-common/src/lib.rs`](../tails-pdp-common/src/lib.rs) | Gemeinsame Typen, Policy-Strukturen, Entscheidungslogik und Konstanten für Userspace und eBPF. |
| [P9] | [`tails-pdp-ebpf/src/main.rs`](../tails-pdp-ebpf/src/main.rs) | eBPF-Crate-Einstieg. |
| [P10] | [`tails-pdp-ebpf/src/hooks.rs`](../tails-pdp-ebpf/src/hooks.rs) | LSM-Hook-Einstiege `file_open` und `socket_bind`. |
| [P11] | [`tails-pdp-ebpf/src/helpers.rs`](../tails-pdp-ebpf/src/helpers.rs) | Kernel-Hilfsfunktionen, z. B. Datei- und Socket-Attributermittlung. |
| [P12] | [`tails-pdp-ebpf/src/maps.rs`](../tails-pdp-ebpf/src/maps.rs) | eBPF-Map-Definitionen, Policy-Maps, Zeit-Maps, Decision-Maps und Tail-Call-Tabelle. |
| [P13] | [`tails-pdp-ebpf/src/logging.rs`](../tails-pdp-ebpf/src/logging.rs) | eBPF-Debug-Logging. |
| [P14] | [`tails-pdp-ebpf/src/policies/`](../tails-pdp-ebpf/src/policies/) | eBPF-Policy-Auswertung, Tail-Call-Ziele und Kombinieren der Entscheidungen. |
| [P15] | [`tails-pdp-ebpf/build.rs`](../tails-pdp-ebpf/build.rs) | Build-Schritte für den eBPF-Teil. |
| [P16] | [`tails-pdp-ebpf/src/vmlinux.rs`](../tails-pdp-ebpf/src/vmlinux.rs) | Kernel-Typen, die aus BTF/vmlinux abgeleitet wurden. |
| [P17] | [`tails-pdp-admintool/src/`](../tails-pdp-admintool/src/) | Admin-Tool, CLI, Map-Zugriffe und Ausgabeformatierung. |
| [P18] | [`scripts/load-test-policies.sh`](../scripts/load-test-policies.sh) | Testskript zum Laden vieler Policies. |
| [P19] | [`examples/`](../examples/) | Beispiel-Policies im SAPL-inspirierten Format. |
| [P20] | [`run.sh`](../run.sh) | Typischer Startbefehl für Entwicklung und Test. |
| [P21] | [`remove_maps.sh`](../remove_maps.sh) | Entfernen gepinnter Maps bei Layout-Änderungen. |
| [P22] | [`README.md`](../README.md) | Kurzanleitung, Bedienbeispiele und Debugging-Hinweise. |
| [P23] | [`tails-pdp/src/stream_attributes.rs`](../tails-pdp/src/stream_attributes.rs) | Lesen von [`stream-attributes/DEFCON.txt`](../environment/DEFCON.txt) und Schreiben der Map `CURRENT_DEFCON`. |
| [P24] | [`stream-attributes/`](../environment/) | Beispielhafter Ablageort für dynamische Stream-Attribute wie `DEFCON.txt`. |

## Externe Quellen

| ID | Quelle | Verwendet für |
| --- | --- | --- |
| [Q1] | [Rust Book: Ownership](https://doc.rust-lang.org/book/ch04-01-what-is-ownership.html) | Grundprinzipien von Rust, Ownership und Speichersicherheit. |
| [Q2] | [Rust Reference: Attributes](https://doc.rust-lang.org/stable/reference/attributes.html) | Erklärung von Attributen wie `#[repr(C)]`. |
| [Q3] | [Aya `EbpfLoader` API](https://docs.rs/aya/latest/aya/struct.EbpfLoader.html) | Laden von eBPF-Objekten im Userspace. |
| [Q4] | [Linux Kernel Documentation: BPF](https://docs.kernel.org/bpf/index.html) | Überblick über eBPF im Linux-Kernel. |
| [Q5] | [Linux Kernel Documentation: BPF Maps](https://docs.kernel.org/bpf/maps.html) | Grundprinzipien von eBPF-Maps. |
| [Q6] | [Linux Kernel Documentation: Array and Per-CPU Array Maps](https://docs.kernel.org/bpf/map_array.html) | Array-Maps und Per-CPU-Maps. |
| [Q7] | [Linux Kernel Documentation: BPF Verifier](https://docs.kernel.org/bpf/verifier.html) | Aufgabe und Arbeitsweise des eBPF-Verifiers. |
| [Q8] | [Linux Kernel Documentation: BPF Design Q&A](https://docs.kernel.org/bpf/bpf_design_QA.html) | eBPF-Designgrenzen, u. a. Stack-Limit. |
| [Q9] | [Linux Kernel Documentation: BPF LSM](https://docs.kernel.org/bpf/prog_lsm.html) | eBPF-Programme für Linux Security Module Hooks. |
| [Q10] | [Linux Kernel Documentation: Linux Security Modules](https://docs.kernel.org/security/lsm.html) | Allgemeines LSM-Modell. |
| [Q11] | [SAPL 4.0.0: Policy Structure](https://sapl.io/docs/4.0.0/2_4_PolicyStructure/) | SAPL-Policy-Struktur als Orientierung für die Text-Policies. |
| [Q12] | [`proc_pid_fd(5)`](https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html) | Bedeutung von `/proc/<pid>/fd` beim FD-Monitoring. |
| [Q13] | [`proc_pid_status(5)`](https://www.man7.org/linux/man-pages/man5/proc_pid_status.5.html) | Prozessstatus und UID-Informationen in `/proc/<pid>/status`. |
| [Q14] | [Linux Kernel Documentation: `/proc/net/tcp`](https://www.kernel.org/doc/html/v5.14/networking/proc_net_tcp.html) | Auswertung aktiver TCP-Sockets über `/proc/net/tcp`. |
| [Q15] | [`ptrace(2)`](https://man7.org/linux/man-pages/man2/ptrace.2.html) | Grundlage für Eingriffe in fremde Prozesse, z. B. FD-Schließen. |
| [Q16] | [bpftool Documentation](https://bpftool.dev/) | Analyse von eBPF-Programmen und Maps mit `bpftool`. |
| [Q17] | [Linux Kernel Documentation: BTF](https://docs.kernel.org/bpf/btf.html) | BPF Type Format und Kernel-Typinformationen. |
| [Q18] | [Aya Programs Module](https://docs.rs/aya/latest/aya/programs/index.html) | Aya-Programmtypen und Attach-Modelle. |
| [Q19] | [Aya Maps Module](https://docs.rs/aya/latest/aya/maps/index.html) | Userspace-Zugriff auf eBPF-Maps mit Aya. |
| [Q20] | [Aya `Ebpf` API](https://docs.rs/aya/latest/aya/struct.Ebpf.html) | Zugriff auf geladene Programme und Maps in Aya. |
| [Q21] | [SAPL 4.0.0: Why SAPL?](https://sapl.io/docs/4.0.0/1_1_WhySAPL/) | Einordnung von SAPL als Policy-Sprache. |
| [Q22] | [`inode(7)`](https://man7.org/linux/man-pages/man7/inode.7.html) | Bedeutung von Inode, Device und Dateimetadaten. |
| [Q23] | [`bpf(2)`](https://man7.org/linux/man-pages/man2/bpf.2.html) | Systemaufruf-Grundlage für eBPF-Programme und Maps. |

## Zitierweise in den Kapiteln

Quellenhinweise stehen direkt im Fließtext der Kapitel. Beispiele:

- `[P10]` bedeutet: Die Aussage bezieht sich auf den konkreten Projektcode in
  [`tails-pdp-ebpf/src/hooks.rs`](../tails-pdp-ebpf/src/hooks.rs).
- `[Q9]` bedeutet: Die allgemeine Aussage zu BPF-LSM stützt sich auf die offizielle
  Linux-Kernel-Dokumentation zu BPF-LSM.

Wenn ein Kapitel sowohl Projektverhalten als auch Linux-, Rust- oder Aya-Grundlagen erklärt, werden
beide Quellenarten genannt.

---

**Previous:** [Glossar](11-glossar.md) | **Next:** -

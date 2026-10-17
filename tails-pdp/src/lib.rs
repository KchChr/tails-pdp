//! Lade- und Tail-Call-Spezifikation des File-Open-LSM-Programms.
//!
//! [`LSM_PROGRAMS`] benennt alle zu ladenden Programme. Nur der Einstiegshook wird
//! angehängt; die weiteren Programme werden über [`FILE_OPEN_TAIL_PROGRAMS`] verkettet.
//! Der ausführbare Runtime-Einstieg initialisiert Maps und Konfiguration vor dem Attach.
//! Linux mit BPF-LSM/BTF und passenden Rechten ist das Ausführungsziel.

/// Tail-Call-Slot der statischen Auswertung.
pub const TAIL_IDX_FILE_OPEN_STATIC: u32 = 0;
/// Tail-Call-Slot der Zeit-/Attributauswertung.
pub const TAIL_IDX_FILE_OPEN_STREAM: u32 = 1;
/// Tail-Call-Slot der Deny-Overrides-Kombination.
pub const TAIL_IDX_FILE_OPEN_COMBINE: u32 = 2;
/// Ein zu ladendes LSM-Programm mit Hookzuordnung und Attachentscheidung.
pub struct LsmProgramSpec {
    /// Symbolname im eingebetteten eBPF-Objekt.
    pub name: &'static str,
    /// Kernel-LSM-Hook für Laden und Verifierprüfung.
    pub hook: &'static str,
    /// Nur `true` hängt das Programm direkt an; Tail-Call-Stufen bleiben unangehängt.
    pub attach: bool,
}

/// Alle zu ladenden File-Open-Programme, einschließlich der drei Tail-Call-Stufen.
pub const LSM_PROGRAMS: [LsmProgramSpec; 4] = [
    LsmProgramSpec {
        name: "file_open",
        hook: "file_open",
        attach: true,
    },
    LsmProgramSpec {
        name: "evaluate_file_open_static_policies",
        hook: "file_open",
        attach: false,
    },
    LsmProgramSpec {
        name: "evaluate_file_open_stream_policies",
        hook: "file_open",
        attach: false,
    },
    LsmProgramSpec {
        name: "combine_file_open",
        hook: "file_open",
        attach: false,
    },
];

/// Zuordnung von Jump-Table-Slots zu eBPF-Programmnamen; muss zu Kernelkonstanten passen.
pub const FILE_OPEN_TAIL_PROGRAMS: [(u32, &str); 3] = [
    (
        TAIL_IDX_FILE_OPEN_STATIC,
        "evaluate_file_open_static_policies",
    ),
    (
        TAIL_IDX_FILE_OPEN_STREAM,
        "evaluate_file_open_stream_policies",
    ),
    (TAIL_IDX_FILE_OPEN_COMBINE, "combine_file_open"),
];

//! Dateibasierte Policyvalidierung und generationenbasierte Kernelmap-Aktivierung.
//!
//! [`PolicyDirectorySync`] lädt rekursiv `.policy`-Dateien unter dem Arbeitsverzeichnis,
//! übersetzt den unterstützten File-Open-Ausschnitt und aktiviert eine vorbereitete Bank.
//! Ungültige laufende Updates erhalten die letzte gültige Generation. Initialfehler
//! und fehlgeschlagene Benachrichtigung des PEP werden als Fehler zurückgegeben.
//! [`verify_pinned_map_layouts`] prüft vorhandene Pins vor dem eBPF-Laden.
//! Die Map-Schnittstelle benötigt Linux und passende Zugriffsrechte.

mod policy_loader;
mod policy_source;

pub use policy_loader::verify_pinned_map_layouts;
pub use policy_source::{PolicyDirectorySync, default_policy_directory};

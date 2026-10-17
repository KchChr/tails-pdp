//! Bibliotheksziel der eBPF-Crate für Cargo-Metadaten und Workspace-Builds.
//!
//! Die Kernelimplementierung liegt im separaten Binary unter `src/main.rs` und dessen
//! Modulen: Requestgewinnung, Maps, statische/Stream-Auswertung und Deny-Overrides.
//! Aya baut dieses `no_std`-Programm für das BPF-Target; die Runtime bettet das Objekt ein.
//! Diese Bibliothek exportiert keine Laufzeit-API.

#![no_std]

// This file exists to enable the library target.

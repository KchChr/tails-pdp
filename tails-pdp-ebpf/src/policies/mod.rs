//! Statische und Stream-Auswertung mit anschließendem Deny-Overrides.
//!
//! Die Stufen tauschen CPU-lokale Entitlementflags und die Policygeneration aus.
//! Beschränkte Schleifen halten die Mapauswertung für den Kernel-Verifier begrenzt.

pub mod combine;
pub mod decision;
pub mod file_open_static_policies;
pub mod file_open_stream_policies;

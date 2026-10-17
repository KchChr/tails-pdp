//! Ereignisgesteuerte Nachbewertung bereits geöffneter Dateideskriptoren.
//!
//! [`run_userspace_pep`] reagiert auf aktivierte Policy-/Attributgenerationen und
//! relevante Zeitgrenzen, bewertet einen `/proc`-Scan und versucht verletzende FDs
//! selektiv zu schließen. Der Entzug ist nur für x86_64-Linux implementiert.
//! Root-/ptrace-Berechtigungen sind erforderlich. Konkurrenz mit FD-Wiederverwendung,
//! Prozessänderungen und vorhandenen Speicherabbildungen ist nicht atomar abgedeckt;
//! ein erfolgreicher Scan oder Race-Test beweist keine globale Race-Freiheit.

mod fd_revoker;
mod pep;

pub use pep::run_userspace_pep;

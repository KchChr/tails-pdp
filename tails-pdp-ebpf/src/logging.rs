//! Opt-in Kernel-Debuglogging mit ausführlichem und reduziertem Deny-Modus.
//!
//! Printk-Ausgaben sind Diagnosehilfe, kein vollständiges Auditjournal und keine
//! kostenfreie Instrumentierung für Performance-Messungen.

use tails_pdp_common::kernel_logging::KernelLogMode;

fn mode() -> KernelLogMode {
    KernelLogMode::from_raw(crate::maps::DEBUG_LOGGING.get(0).copied().unwrap_or(0))
}

pub(crate) fn debug_enabled() -> bool {
    mode().logs_verbose()
}

pub(crate) fn deny_debug_enabled() -> bool {
    mode().logs_denials()
}

/// Meldungen, die sowohl im ausführlichen als auch im Deny-Modus sichtbar sind.
#[macro_export]
macro_rules! deny_printk {
    ($fmt:expr $(, $arg:expr)* $(,)?) => {{
        if $crate::logging::deny_debug_enabled() {
            unsafe {
                aya_ebpf::bpf_printk!($fmt $(, $arg)*);
            }
        }
    }};
}

#[macro_export]
macro_rules! debug_printk {
    ($fmt:expr $(, $arg:expr)* $(,)?) => {{
        if $crate::logging::debug_enabled() {
            unsafe {
                aya_ebpf::bpf_printk!($fmt $(, $arg)*);
            }
        }
    }};
}

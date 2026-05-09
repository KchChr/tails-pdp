pub(crate) fn debug_enabled() -> bool {
    crate::maps::DEBUG_LOGGING.get(0).copied().unwrap_or(0) != 0
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

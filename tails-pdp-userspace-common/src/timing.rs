//! Opt-in measurement markers. Linux CLOCK_MONOTONIC matches Python monotonic_ns.
use std::sync::OnceLock;

pub fn mark(event: &str, generation: u32) {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    if !*ENABLED.get_or_init(|| std::env::var("TAILS_PDP_TIMING").as_deref() == Ok("1")) {
        return;
    }
    #[cfg(target_os = "linux")]
    {
        let mut ts = std::mem::MaybeUninit::<libc::timespec>::uninit();
        if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, ts.as_mut_ptr()) } == 0 {
            let ts = unsafe { ts.assume_init() };
            let ns = ts.tv_sec as u128 * 1_000_000_000 + ts.tv_nsec as u128;
            eprintln!("PDP_TIMING event={event} ns={ns} generation={generation}");
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = (event, generation);
}

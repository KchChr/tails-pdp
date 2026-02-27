#![no_std]
#![no_main]

use aya_ebpf::{macros::lsm, programs::LsmContext};

#[lsm(hook = "file_open")]
pub fn file_open(ctx: LsmContext) -> i32 {
    // Phase 1: minimal verifier-friendly program.
    //info!(&ctx, "tails-pdp: file_open hook called");
    0
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";


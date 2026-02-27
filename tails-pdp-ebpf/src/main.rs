#![no_std]
#![no_main]

use aya_ebpf::{EbpfContext, macros::lsm, programs::LsmContext};

#[lsm(hook = "file_open")]
pub fn file_open(ctx: LsmContext) -> i32 {
    // Phase 1: minimal verifier-friendly program.
    unsafe {
        aya_ebpf::bpf_printk!(b"tails-pdp: file_open pid=%d", ctx.pid());
    }
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

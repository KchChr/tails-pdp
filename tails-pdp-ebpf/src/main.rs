#![no_std]
#![no_main]
#![allow(unsafe_op_in_unsafe_fn)]

mod helpers;
mod hooks;
mod logging;
mod maps;
mod policies;
mod vmlinux;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";

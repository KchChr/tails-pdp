//! Kernel-Binary mit File-Open-LSM-Hook und verifierbegrenzter Tail-Call-Kette.
//!
//! Gemeinsame ABI-Typen stammen aus `tails-pdp-common`; generierte Kerneltypen aus
//! `vmlinux` werden zur Requestgewinnung verwendet. Das Objekt wird durch Aya gebaut
//! und in die Userspace-Runtime eingebettet. Es ist kein separat gestarteter Prozess.

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

use aya_ebpf::{macros::lsm, programs::LsmContext};

use crate::maps::DECISIONS;

#[lsm(hook = "file_open")]
pub fn combine(_ctx: LsmContext) -> i32 {
    unsafe {
        aya_ebpf::bpf_printk!(b"tails-pdp: combine");
    }
    match DECISIONS.get(0) {
        Some(v) if *v != 0 => {
            unsafe {
                aya_ebpf::bpf_printk!(b"DENY");
            }
            -1
        }
        _ => {
            unsafe {
                aya_ebpf::bpf_printk!(b"PERMIT");
            }
            0
        }
    }
}

use aya_ebpf::{macros::lsm, programs::LsmContext};

use crate::maps::DECISIONS;

fn combine_decision() -> i32 {
    match DECISIONS.get(0) {
        Some(v) if *v != 0 => -1,
        _ => 0,
    }
}

#[lsm(hook = "file_open")]
pub fn combine_file_open(_ctx: LsmContext) -> i32 {
    let decision = combine_decision();
    unsafe {
        if decision != 0 {
            aya_ebpf::bpf_printk!(b"file_open final=deny");
        } else {
            aya_ebpf::bpf_printk!(b"file_open final=permit");
        }
    }
    decision
}

#[lsm(hook = "socket_bind")]
pub fn combine_socket_bind(_ctx: LsmContext) -> i32 {
    let decision = combine_decision();
    unsafe {
        if decision != 0 {
            aya_ebpf::bpf_printk!(b"socket_bind final=deny");
        } else {
            aya_ebpf::bpf_printk!(b"socket_bind final=permit");
        }
    }
    decision
}

#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{lsm, map},
    maps::ProgramArray,
    programs::LsmContext,
};
use aya_ebpf::maps::Array;

const TAIL_IDX_POLICY_1: u32 = 0;
const TAIL_IDX_POLICY_2: u32 = 1;
const TAIL_IDX_POLICY_3: u32 = 2;
const COMBINE: u32 = 3;

#[map]
static POLICY_JUMP_TABLE: ProgramArray = ProgramArray::with_max_entries(4, 0);

#[map]
static DECISIONS : Array<i32> = Array::with_max_entries(1, 0);

#[lsm(hook = "file_open")]
pub fn file_open(ctx: LsmContext) -> i32 {
    unsafe {
        aya_ebpf::bpf_printk!(b"tails-pdp: file_open entry");
        let _ = POLICY_JUMP_TABLE.tail_call(&ctx, TAIL_IDX_POLICY_1);
    }

}

#[lsm(hook = "file_open")]
pub fn policy_1(ctx: LsmContext) -> i32 {
    let _ = DECISIONS.set(0, 1, 0);
    unsafe {
        aya_ebpf::bpf_printk!(b"tails-pdp: policy_1");
        let _ = POLICY_JUMP_TABLE.tail_call(&ctx, TAIL_IDX_POLICY_2);
    }

    0
}

#[lsm(hook = "file_open")]
pub fn policy_2(ctx: LsmContext) -> i32 {
    unsafe {
        aya_ebpf::bpf_printk!(b"tails-pdp: policy_2");
        let _ = POLICY_JUMP_TABLE.tail_call(&ctx, TAIL_IDX_POLICY_3);
    }
    0
}

#[lsm(hook = "file_open")]
pub fn policy_3(ctx: LsmContext) -> i32 {
    unsafe {
        aya_ebpf::bpf_printk!(b"tails-pdp: policy_3");
        let _ = POLICY_JUMP_TABLE.tail_call(&ctx, COMBINE);
    }
    0
}

#[lsm(hook = "file_open")]
pub fn combine(ctx: LsmContext) -> i32 {
    unsafe {
        aya_ebpf::bpf_printk!(b"tails-pdp: combine");
    }
    match DECISIONS.get(0) {
        Some(v) if *v != 0 => {
            unsafe {
                aya_ebpf::bpf_printk!(b"DENY");
            }
            -1}, // deny
        _ => {
            unsafe {
                aya_ebpf::bpf_printk!(b"PERMIT");
            }
            0},                   // permit/default
    }

}


#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";

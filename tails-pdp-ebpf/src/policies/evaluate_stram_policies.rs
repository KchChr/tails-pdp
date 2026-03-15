use aya_ebpf::{macros::lsm, programs::LsmContext};

use crate::maps::{COMBINE, POLICY_JUMP_TABLE};

#[lsm(hook = "file_open")]
pub fn evaluate_stram_policies(ctx: LsmContext) -> i32 {
    unsafe {
        aya_ebpf::bpf_printk!(b"tails-pdp: evaluate_stram_policies");
        let _ = POLICY_JUMP_TABLE.tail_call(&ctx, COMBINE);
    }
    0
}

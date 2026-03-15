use aya_ebpf::{EbpfContext, macros::lsm, programs::LsmContext};
use tails_pdp_common::{COMMAND_LEN, PolicyAction, RESOURCE_LEN};

use crate::{
    maps::{POLICY_JUMP_TABLE, TAIL_IDX_POLICY_1},
    policies::evaluate_static_policies::evaluate_policies,
};

#[lsm(hook = "file_open")]
pub fn file_open(ctx: LsmContext) -> i32 {
    unsafe {
        aya_ebpf::bpf_printk!(b"tails-pdp: file_open entry");
        let _ = POLICY_JUMP_TABLE.tail_call(&ctx, TAIL_IDX_POLICY_1);
    }
    0
}

#[lsm(hook = "task_setnice")]
pub fn task_setnice(ctx: LsmContext) -> i32 {
    let subject = ctx.uid();
    let command = ctx.command().unwrap_or([0; COMMAND_LEN]);
    let resource = [0; RESOURCE_LEN];
    let decision = evaluate_policies(subject, PolicyAction::TaskSetNice, &command, &resource);

    unsafe {
        aya_ebpf::bpf_printk!(b"tails-pdp: task_setnice entry");
    }

    if decision != 0 { -1 } else { 0 }
}

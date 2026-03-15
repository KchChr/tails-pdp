use aya_ebpf::{EbpfContext, macros::lsm, programs::LsmContext};
use tails_pdp_common::{COMMAND_LEN, PolicyAction};

use crate::{
    helpers::{evaluate_policies, read_file_open_resource},
    maps::{DECISIONS, POLICY_JUMP_TABLE, TAIL_IDX_POLICY_2},
};

#[lsm(hook = "file_open")]
pub fn evaluate_static_policys(ctx: LsmContext) -> i32 {
    let subject = ctx.uid();
    let command = ctx.command().unwrap_or([0; COMMAND_LEN]);
    let resource = read_file_open_resource(&ctx);
    let decision = evaluate_policies(subject, PolicyAction::FileOpen, &command, &resource);
    let _ = DECISIONS.set(0, decision, 0);

    unsafe {
        aya_ebpf::bpf_printk!(b"tails-pdp: evaluate_static_policys");
        let _ = POLICY_JUMP_TABLE.tail_call(&ctx, TAIL_IDX_POLICY_2);
    }

    0
}

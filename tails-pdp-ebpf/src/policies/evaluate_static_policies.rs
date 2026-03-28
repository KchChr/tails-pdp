use aya_ebpf::{EbpfContext, macros::lsm, programs::LsmContext};
use tails_pdp_common::{ANY_SUBJECT, COMMAND_LEN, PolicyAction, StaticPolicy};

use crate::{
    helpers::read_file_open_resource_identity,
    maps::{
        DECISIONS, POLICY_JUMP_TABLE, STATIC_POLICY, STATIC_POLICY_MAX_ENTRIES, TAIL_IDX_POLICY_2,
    },
};

fn matches_subject(subject: u32, current_subject: u32) -> bool {
    subject == ANY_SUBJECT || subject == current_subject
}

fn matches_bytes<const N: usize>(policy_value: &[u8; N], current_value: &[u8; N]) -> bool {
    policy_value[0] == 0 || policy_value == current_value
}

fn matches_resource(policy: &StaticPolicy, current_device: u64, current_inode: u64) -> bool {
    policy.matches_any_resource()
        || (policy.resource_device == current_device && policy.resource_inode == current_inode)
}

fn evaluate_static_policy(
    current_subject: u32,
    current_action: PolicyAction,
    current_command: &[u8; COMMAND_LEN],
    current_resource_device: u64,
    current_resource_inode: u64,
    policy: &StaticPolicy,
) -> Option<i32> {
    if policy.enabled == 0 {
        return None;
    }

    if policy.action != current_action {
        return None;
    }

    if !matches_subject(policy.subject, current_subject) {
        return None;
    }

    if !matches_bytes(&policy.command, current_command) {
        return None;
    }

    if !matches_resource(policy, current_resource_device, current_resource_inode) {
        return None;
    }

    Some(policy.entitlement.decision())
}

pub(crate) fn evaluate_policies(
    current_subject: u32,
    current_action: PolicyAction,
    current_command: &[u8; COMMAND_LEN],
    current_resource_device: u64,
    current_resource_inode: u64,
) -> i32 {
    let mut decision = 0;
    let mut index = 0;

    while index < STATIC_POLICY_MAX_ENTRIES {
        if let Some(policy) = STATIC_POLICY.get(index) {
            if let Some(policy_decision) = evaluate_static_policy(
                current_subject,
                current_action,
                current_command,
                current_resource_device,
                current_resource_inode,
                policy,
            ) {
                if policy_decision != 0 {
                    decision = 1;
                    break;
                }
            }
        }
        index += 1;
    }

    decision
}

#[lsm(hook = "file_open")]
pub fn evaluate_static_policies(ctx: LsmContext) -> i32 {
    let subject = ctx.uid();
    let command = ctx.command().unwrap_or([0; COMMAND_LEN]);
    let (resource_device, resource_inode) = read_file_open_resource_identity(&ctx);
    let decision = evaluate_policies(
        subject,
        PolicyAction::FileOpen,
        &command,
        resource_device,
        resource_inode,
    );
    let _ = DECISIONS.set(0, decision, 0);

    unsafe {
        aya_ebpf::bpf_printk!(b"tails-pdp: evaluate_static_policies");
        let _ = POLICY_JUMP_TABLE.tail_call(&ctx, TAIL_IDX_POLICY_2);
    }

    0
}

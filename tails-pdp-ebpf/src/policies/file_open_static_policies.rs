use aya_ebpf::{EbpfContext, macros::lsm, programs::LsmContext};
use tails_pdp_common::{
    ANY_SUBJECT, COMMAND_LEN, FILE_OPEN_STATIC_POLICY_MAX_ENTRIES, FileOpenStaticPolicy,
};

use crate::{
    helpers::{FileOpenResource, read_file_open_resource},
    maps::{DECISIONS, FILE_OPEN_JUMP_TABLE, FILE_OPEN_STATIC_POLICIES, TAIL_IDX_FILE_OPEN_STREAM},
};

fn matches_subject(subject: u32, current_subject: u32) -> bool {
    subject == ANY_SUBJECT || subject == current_subject
}

fn matches_bytes<const N: usize>(policy_value: &[u8; N], current_value: &[u8; N]) -> bool {
    policy_value[0] == 0 || policy_value == current_value
}

fn matches_resource(policy: &FileOpenStaticPolicy, resource: &FileOpenResource) -> bool {
    policy.matches_any_resource()
        || (policy.resource_device == resource.device && policy.resource_inode == resource.inode)
}

fn evaluate_policy(
    current_subject: u32,
    current_command: &[u8; COMMAND_LEN],
    resource: &FileOpenResource,
    policy: &FileOpenStaticPolicy,
) -> Option<i32> {
    if policy.enabled == 0 {
        return None;
    }
    if !matches_subject(policy.subject, current_subject) {
        return None;
    }
    if !matches_bytes(&policy.command, current_command) {
        return None;
    }
    if !matches_resource(policy, resource) {
        return None;
    }
    Some(policy.entitlement.decision())
}

pub(crate) fn evaluate_policies(
    current_subject: u32,
    current_command: &[u8; COMMAND_LEN],
    resource: &FileOpenResource,
) -> i32 {
    let mut decision = 0;
    let mut index = 0;
    let mut matched_index = u32::MAX;

    while index < FILE_OPEN_STATIC_POLICY_MAX_ENTRIES {
        if let Some(policy) = FILE_OPEN_STATIC_POLICIES.get(index) {
            if let Some(policy_decision) =
                evaluate_policy(current_subject, current_command, resource, policy)
            {
                matched_index = index;
                if policy_decision != 0 {
                    decision = 1;
                    break;
                }
            }
        }
        index += 1;
    }

    unsafe {
        aya_ebpf::bpf_printk!(
            b"fos res=%d idx=%d uid=%d dev=%llu ino=%llu cmd=%s",
            decision as u32,
            matched_index,
            current_subject,
            resource.device,
            resource.inode,
            current_command.as_ptr(),
        );
    }

    decision
}

#[lsm(hook = "file_open")]
pub fn evaluate_file_open_static_policies(ctx: LsmContext) -> i32 {
    let subject = ctx.uid();
    let command = ctx.command().unwrap_or([0; COMMAND_LEN]);
    let resource = read_file_open_resource(&ctx);
    let decision = evaluate_policies(subject, &command, &resource);
    let _ = DECISIONS.set(0, decision, 0);

    unsafe {
        let _ = FILE_OPEN_JUMP_TABLE.tail_call(&ctx, TAIL_IDX_FILE_OPEN_STREAM);
    }

    0
}

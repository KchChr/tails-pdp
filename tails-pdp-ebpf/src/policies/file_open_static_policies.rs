use aya_ebpf::{EbpfContext, macros::lsm, programs::LsmContext};
use tails_pdp_common::{
    ANY_SUBJECT, COMMAND_LEN, Entitlement, FILE_OPEN_STATIC_POLICY_MAX_ENTRIES,
    FileOpenStaticPolicy,
};

use crate::{
    helpers::{FileOpenResource, read_file_open_resource},
    maps::{FILE_OPEN_JUMP_TABLE, FILE_OPEN_STATIC_POLICIES, TAIL_IDX_FILE_OPEN_STREAM},
    policies::decision::DecisionState,
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

fn is_policy_applicable(
    current_subject: u32,
    current_command: &[u8; COMMAND_LEN],
    resource: &FileOpenResource,
    policy: &FileOpenStaticPolicy,
) -> bool {
    if policy.enabled == 0 {
        return false;
    }
    if !matches_subject(policy.subject, current_subject) {
        return false;
    }
    if !matches_bytes(&policy.command, current_command) {
        return false;
    }
    if !matches_resource(policy, resource) {
        return false;
    }
    true
}

fn evaluate_policy(
    current_subject: u32,
    current_command: &[u8; COMMAND_LEN],
    resource: &FileOpenResource,
    policy: &FileOpenStaticPolicy,
) -> Option<Entitlement> {
    if !is_policy_applicable(current_subject, current_command, resource, policy) {
        return None;
    }

    Some(policy.entitlement)
}

pub(crate) fn evaluate_policies(
    current_subject: u32,
    current_command: &[u8; COMMAND_LEN],
    resource: &FileOpenResource,
) -> DecisionState {
    let mut state = DecisionState::empty();
    let mut index = 0;
    let mut matched_deny_index = u32::MAX;
    let mut matched_permit_index = u32::MAX;

    while index < FILE_OPEN_STATIC_POLICY_MAX_ENTRIES {
        if let Some(policy) = FILE_OPEN_STATIC_POLICIES.get(index) {
            if let Some(entitlement) =
                evaluate_policy(current_subject, current_command, resource, policy)
            {
                match entitlement {
                    Entitlement::Deny => {
                        matched_deny_index = matched_deny_index.min(index);
                    }
                    Entitlement::Permit => {
                        matched_permit_index = matched_permit_index.min(index);
                    }
                }
                state.record(entitlement);
            }
        }
        index += 1;
    }

    unsafe {
        aya_ebpf::bpf_printk!(
            b"fos deny=%d permit=%d didx=%d pidx=%d uid=%d dev=%llu ino=%llu cmd=%s",
            state.deny,
            state.permit,
            matched_deny_index,
            matched_permit_index,
            current_subject,
            resource.device,
            resource.inode,
            current_command.as_ptr(),
        );
    }

    state
}

#[lsm(hook = "file_open")]
pub fn evaluate_file_open_static_policies(ctx: LsmContext) -> i32 {
    let subject = ctx.uid();
    let command = ctx.command().unwrap_or([0; COMMAND_LEN]);
    let resource = read_file_open_resource(&ctx);
    let decision_state = evaluate_policies(subject, &command, &resource);
    decision_state.write_to_map();

    unsafe {
        let _ = FILE_OPEN_JUMP_TABLE.tail_call(&ctx, TAIL_IDX_FILE_OPEN_STREAM);
    }

    0
}

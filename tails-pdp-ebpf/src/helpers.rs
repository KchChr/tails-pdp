use core::ptr::addr_of;

use aya_ebpf::{
    helpers::{bpf_probe_read_kernel, bpf_probe_read_kernel_str_bytes},
    programs::LsmContext,
};
use tails_pdp_common::{ANY_SUBJECT, COMMAND_LEN, PolicyAction, RESOURCE_LEN, StaticPolicy};

use crate::{
    maps::{STATIC_POLICY, STATIC_POLICY_MAX_ENTRIES},
    vmlinux,
};

fn matches_subject(subject: u32, current_subject: u32) -> bool {
    subject == ANY_SUBJECT || subject == current_subject
}

fn matches_bytes<const N: usize>(policy_value: &[u8; N], current_value: &[u8; N]) -> bool {
    policy_value[0] == 0 || policy_value == current_value
}

pub(crate) fn read_file_open_resource(ctx: &LsmContext) -> [u8; RESOURCE_LEN] {
    let mut resource = [0; RESOURCE_LEN];
    let file_ptr: *const vmlinux::file = ctx.arg(0);
    if file_ptr.is_null() {
        return resource;
    }

    let Ok(dentry_ptr) = (unsafe { bpf_probe_read_kernel(addr_of!((*file_ptr).f_path.dentry)) })
    else {
        return resource;
    };
    if dentry_ptr.is_null() {
        return resource;
    }

    let Ok(name_ptr) = (unsafe { bpf_probe_read_kernel(addr_of!((*dentry_ptr).d_name.name)) })
    else {
        return resource;
    };
    if name_ptr.is_null() {
        return resource;
    }

    let _ = unsafe { bpf_probe_read_kernel_str_bytes(name_ptr.cast(), &mut resource) };
    resource
}

fn evaluate_static_policy(
    current_subject: u32,
    current_action: PolicyAction,
    current_command: &[u8; COMMAND_LEN],
    current_resource: &[u8; RESOURCE_LEN],
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

    if !matches_bytes(&policy.resource, current_resource) {
        return None;
    }

    Some(policy.entitlement.decision())
}

pub(crate) fn evaluate_policies(
    current_subject: u32,
    current_action: PolicyAction,
    current_command: &[u8; COMMAND_LEN],
    current_resource: &[u8; RESOURCE_LEN],
) -> i32 {
    let mut decision = 0;
    let mut index = 0;

    while index < STATIC_POLICY_MAX_ENTRIES {
        if let Some(policy) = STATIC_POLICY.get(index) {
            if let Some(policy_decision) = evaluate_static_policy(
                current_subject,
                current_action,
                current_command,
                current_resource,
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

use aya_ebpf::{EbpfContext, macros::lsm, programs::LsmContext};
use tails_pdp_common::{
    ANY_SUBJECT, COMMAND_LEN, PolicyAction, SOCKET_IP_LEN, STATIC_POLICY_SLOTS_PER_HOOK,
    SocketFamily, SocketTransport, StaticPolicy,
};

use crate::{
    helpers::{ResourceIdentity, read_file_open_resource_identity},
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

fn matches_socket_ip(
    policy: &StaticPolicy,
    current_family: SocketFamily,
    current_ip: &[u8; SOCKET_IP_LEN],
) -> bool {
    if policy.matches_any_socket_ip() {
        return true;
    }

    match current_family {
        SocketFamily::Inet => policy.socket_ip[..4] == current_ip[..4],
        SocketFamily::Inet6 => policy.socket_ip == *current_ip,
        SocketFamily::Any => false,
    }
}

fn matches_resource(
    policy: &StaticPolicy,
    current_action: PolicyAction,
    resource: &ResourceIdentity,
) -> bool {
    match current_action {
        PolicyAction::FileOpen => {
            policy.matches_any_resource()
                || (policy.resource_device == resource.file_device
                    && policy.resource_inode == resource.file_inode)
        }
        PolicyAction::SocketBind => {
            let family_matches = policy.socket_family == SocketFamily::Any
                || policy.socket_family == resource.socket_family;
            let transport_matches = policy.socket_transport == SocketTransport::Any
                || policy.socket_transport == resource.socket_transport;
            let port_matches =
                policy.socket_port == 0 || policy.socket_port == resource.socket_port;
            family_matches
                && transport_matches
                && port_matches
                && matches_socket_ip(policy, resource.socket_family, &resource.socket_ip)
        }
        PolicyAction::TaskSetNice => true,
    }
}

fn evaluate_static_policy(
    current_subject: u32,
    current_action: PolicyAction,
    current_command: &[u8; COMMAND_LEN],
    resource: &ResourceIdentity,
    policy: &StaticPolicy,
) -> Option<i32> {
    if policy.enabled == 0 {
        return None;
    }

    let action_matches = policy.action == current_action;
    let subject_matches = matches_subject(policy.subject, current_subject);
    let command_matches = matches_bytes(&policy.command, current_command);
    let resource_matches = matches_resource(policy, current_action, resource);

    unsafe {
        aya_ebpf::bpf_printk!(
            b"static uid=%d act=%d subj=%d cmd=%d res=%d comm=%s cur_dev=%llu cur_ino=%llu pol_dev=%llu pol_ino=%llu",
            current_subject,
            action_matches as u32,
            subject_matches as u32,
            command_matches as u32,
            resource_matches as u32,
            current_command.as_ptr(),
            resource.file_device,
            resource.file_inode,
            policy.resource_device,
            policy.resource_inode,
        );
    }

    if !action_matches {
        return None;
    }

    if !subject_matches {
        return None;
    }

    if !command_matches {
        return None;
    }

    if !resource_matches {
        return None;
    }

    Some(policy.entitlement.decision())
}

pub(crate) fn evaluate_policies(
    current_subject: u32,
    current_action: PolicyAction,
    current_command: &[u8; COMMAND_LEN],
    resource: &ResourceIdentity,
) -> i32 {
    let mut decision = 0;
    let mut index = current_action.segment_start(STATIC_POLICY_SLOTS_PER_HOOK);
    let end = current_action.segment_end(STATIC_POLICY_SLOTS_PER_HOOK);

    while index < end && index < STATIC_POLICY_MAX_ENTRIES {
        if let Some(policy) = STATIC_POLICY.get(index) {
            if let Some(policy_decision) = evaluate_static_policy(
                current_subject,
                current_action,
                current_command,
                resource,
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
    let resource = read_file_open_resource_identity(&ctx);
    let decision = evaluate_policies(subject, PolicyAction::FileOpen, &command, &resource);
    let _ = DECISIONS.set(0, decision, 0);

    unsafe {
        aya_ebpf::bpf_printk!(b"tails-pdp: evaluate_static_policies");
        let _ = POLICY_JUMP_TABLE.tail_call(&ctx, TAIL_IDX_POLICY_2);
    }

    0
}

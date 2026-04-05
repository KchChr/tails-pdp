use aya_ebpf::{EbpfContext, macros::lsm, programs::LsmContext};
use tails_pdp_common::{
    ANY_SUBJECT, Entitlement, SOCKET_BIND_STATIC_POLICY_MAX_ENTRIES, SOCKET_IP_LEN,
    SocketBindStaticPolicy, SocketFamily, SocketTransport,
};

use crate::{
    helpers::{SocketBindResource, read_socket_bind_resource},
    maps::{SOCKET_BIND_JUMP_TABLE, SOCKET_BIND_STATIC_POLICIES, TAIL_IDX_SOCKET_BIND_STREAM},
    policies::decision::DecisionState,
};

fn matches_subject(subject: u32, current_subject: u32) -> bool {
    subject == ANY_SUBJECT || subject == current_subject
}

fn matches_socket_ip(
    policy: &SocketBindStaticPolicy,
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

fn matches_resource(policy: &SocketBindStaticPolicy, resource: &SocketBindResource) -> bool {
    let family_matches =
        policy.socket_family == SocketFamily::Any || policy.socket_family == resource.family;
    let transport_matches = policy.socket_transport == SocketTransport::Any
        || policy.socket_transport == resource.transport;
    let port_matches = policy.socket_port == 0 || policy.socket_port == resource.port;
    family_matches
        && transport_matches
        && port_matches
        && matches_socket_ip(policy, resource.family, &resource.ip)
}

fn is_policy_applicable(
    current_subject: u32,
    resource: &SocketBindResource,
    policy: &SocketBindStaticPolicy,
) -> bool {
    if policy.enabled == 0 {
        return false;
    }
    if !matches_subject(policy.subject, current_subject) {
        return false;
    }
    if !matches_resource(policy, resource) {
        return false;
    }
    true
}

fn evaluate_policy(
    current_subject: u32,
    resource: &SocketBindResource,
    policy: &SocketBindStaticPolicy,
) -> Option<Entitlement> {
    if !is_policy_applicable(current_subject, resource, policy) {
        return None;
    }

    Some(policy.entitlement)
}

pub(crate) fn evaluate_policies(
    current_subject: u32,
    resource: &SocketBindResource,
) -> DecisionState {
    let mut state = DecisionState::empty();
    let mut index = 0;
    let mut matched_deny_index = u32::MAX;
    let mut matched_permit_index = u32::MAX;

    while index < SOCKET_BIND_STATIC_POLICY_MAX_ENTRIES {
        if let Some(policy) = SOCKET_BIND_STATIC_POLICIES.get(index) {
            if let Some(entitlement) = evaluate_policy(current_subject, resource, policy) {
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
            b"sbs deny=%d permit=%d didx=%d pidx=%d uid=%d fam=%d tr=%d port=%d",
            state.deny,
            state.permit,
            matched_deny_index,
            matched_permit_index,
            current_subject,
            resource.family as u32,
            resource.transport as u32,
            resource.port as u32,
        );
    }

    state
}

#[lsm(hook = "socket_bind")]
pub fn evaluate_socket_bind_static_policies(ctx: LsmContext) -> i32 {
    let subject = ctx.uid();
    let resource = read_socket_bind_resource(&ctx);
    let decision_state = evaluate_policies(subject, &resource);
    decision_state.write_to_map();

    unsafe {
        let _ = SOCKET_BIND_JUMP_TABLE.tail_call(&ctx, TAIL_IDX_SOCKET_BIND_STREAM);
    }

    0
}

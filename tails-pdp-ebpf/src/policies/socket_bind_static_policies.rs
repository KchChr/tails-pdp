use aya_ebpf::{EbpfContext, macros::lsm, programs::LsmContext};
use tails_pdp_common::{
    ANY_SUBJECT, SOCKET_BIND_STATIC_POLICY_MAX_ENTRIES, SOCKET_IP_LEN, SocketBindStaticPolicy,
    SocketFamily, SocketTransport,
};

use crate::{
    helpers::{SocketBindResource, read_socket_bind_resource},
    maps::{
        DECISIONS, POLICY_JUMP_TABLE, SOCKET_BIND_STATIC_POLICIES, TAIL_IDX_SOCKET_BIND_STREAM,
    },
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

fn evaluate_policy(
    current_subject: u32,
    resource: &SocketBindResource,
    policy: &SocketBindStaticPolicy,
) -> Option<i32> {
    if policy.enabled == 0 {
        return None;
    }
    if !matches_subject(policy.subject, current_subject) {
        return None;
    }
    if !matches_resource(policy, resource) {
        return None;
    }
    Some(policy.entitlement.decision())
}

pub(crate) fn evaluate_policies(current_subject: u32, resource: &SocketBindResource) -> i32 {
    let mut decision = 0;
    let mut index = 0;
    let mut matched_index = u32::MAX;

    while index < SOCKET_BIND_STATIC_POLICY_MAX_ENTRIES {
        if let Some(policy) = SOCKET_BIND_STATIC_POLICIES.get(index) {
            if let Some(policy_decision) = evaluate_policy(current_subject, resource, policy) {
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
            b"sbs res=%d idx=%d uid=%d fam=%d tr=%d port=%d",
            decision as u32,
            matched_index,
            current_subject,
            resource.family as u32,
            resource.transport as u32,
            resource.port as u32,
        );
    }

    decision
}

#[lsm(hook = "socket_bind")]
pub fn evaluate_socket_bind_static_policies(ctx: LsmContext) -> i32 {
    let subject = ctx.uid();
    let resource = read_socket_bind_resource(&ctx);
    let decision = evaluate_policies(subject, &resource);
    let _ = DECISIONS.set(0, decision, 0);

    unsafe {
        let _ = POLICY_JUMP_TABLE.tail_call(&ctx, TAIL_IDX_SOCKET_BIND_STREAM);
    }

    0
}

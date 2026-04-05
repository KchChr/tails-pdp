use aya_ebpf::{EbpfContext, macros::lsm, programs::LsmContext};
use tails_pdp_common::{
    ANY_SUBJECT, Entitlement, SOCKET_BIND_STREAM_POLICY_MAX_ENTRIES, SOCKET_IP_LEN,
    SocketBindStreamPolicy, SocketFamily, SocketTransport, StreamAttribute, StreamOperator,
};

use crate::{
    helpers::{SocketBindResource, read_socket_bind_resource},
    maps::{
        CURRENT_TIME, DECISIONS, POLICY_JUMP_TABLE, SOCKET_BIND_STREAM_POLICIES,
        TAIL_IDX_SOCKET_BIND_COMBINE,
    },
};

fn matches_operator(operator: StreamOperator, left: u64, right: u64) -> bool {
    match operator {
        StreamOperator::LessThan => left < right,
        StreamOperator::LessThanOrEqual => left <= right,
        StreamOperator::Equal => left == right,
        StreamOperator::GreaterThanOrEqual => left >= right,
        StreamOperator::GreaterThan => left > right,
    }
}

fn matches_socket_ip(
    policy: &SocketBindStreamPolicy,
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

fn matches_resource(policy: &SocketBindStreamPolicy, resource: &SocketBindResource) -> bool {
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
    current_time: u64,
    policy: &SocketBindStreamPolicy,
) -> Option<i32> {
    if policy.enabled == 0 {
        return None;
    }
    if policy.subject != ANY_SUBJECT && policy.subject != current_subject {
        return None;
    }
    if !matches_resource(policy, resource) {
        return None;
    }

    let condition = match policy.attribute {
        StreamAttribute::Time => {
            if policy.modulo == 0 {
                return None;
            }
            matches_operator(policy.operator, current_time % policy.modulo, policy.value)
        }
    };

    Some(if condition {
        policy.entitlement.decision()
    } else {
        policy.entitlement.inverse().decision()
    })
}

pub(crate) fn evaluate_policies(
    current_subject: u32,
    resource: &SocketBindResource,
    current_time: u64,
) -> i32 {
    let mut decision = 0;
    let mut index = 0;
    let mut matched_index = u32::MAX;

    while index < SOCKET_BIND_STREAM_POLICY_MAX_ENTRIES {
        if let Some(policy) = SOCKET_BIND_STREAM_POLICIES.get(index) {
            if let Some(policy_decision) =
                evaluate_policy(current_subject, resource, current_time, policy)
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
            b"sbsm res=%d idx=%d uid=%d t=%llu fam=%d tr=%d port=%d",
            decision as u32,
            matched_index,
            current_subject,
            current_time,
            resource.family as u32,
            resource.transport as u32,
            resource.port as u32,
        );
    }

    decision
}

#[lsm(hook = "socket_bind")]
pub fn evaluate_socket_bind_stream_policies(ctx: LsmContext) -> i32 {
    let current_decision = DECISIONS.get(0).copied().unwrap_or(0);
    let current_subject = ctx.uid();
    let resource = read_socket_bind_resource(&ctx);
    let current_time = CURRENT_TIME.get(0).copied().unwrap_or(0);
    let stream_decision = evaluate_policies(current_subject, &resource, current_time);
    let decision = if current_decision != 0 || stream_decision != 0 {
        Entitlement::Deny.decision()
    } else {
        Entitlement::Permit.decision()
    };
    let _ = DECISIONS.set(0, decision, 0);

    unsafe {
        let _ = POLICY_JUMP_TABLE.tail_call(&ctx, TAIL_IDX_SOCKET_BIND_COMBINE);
    }

    0
}

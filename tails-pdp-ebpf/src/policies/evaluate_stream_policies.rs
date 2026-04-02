use aya_ebpf::{EbpfContext, macros::lsm, programs::LsmContext};
use tails_pdp_common::{
    ANY_SUBJECT, Entitlement, PolicyAction, SOCKET_IP_LEN, STREAM_POLICY_SLOTS_PER_HOOK,
    SocketFamily, SocketTransport, StreamAttribute, StreamOperator, StreamPolicy,
};

use crate::{
    helpers::{ResourceIdentity, read_file_open_resource_identity},
    maps::{
        COMBINE, CURRENT_TIME, DECISIONS, POLICY_JUMP_TABLE, STREAM_POLICY,
        STREAM_POLICY_MAX_ENTRIES,
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

fn evaluate_stream_policy(
    current_subject: u32,
    current_action: PolicyAction,
    resource: &ResourceIdentity,
    current_time: u64,
    policy: &StreamPolicy,
) -> Option<i32> {
    if policy.enabled == 0 {
        return None;
    }

    if policy.action != current_action {
        return None;
    }

    if policy.subject != ANY_SUBJECT && policy.subject != current_subject {
        return None;
    }

    match current_action {
        PolicyAction::FileOpen => {
            if !policy.matches_any_resource()
                && (policy.resource_device != resource.file_device
                    || policy.resource_inode != resource.file_inode)
            {
                return None;
            }
        }
        PolicyAction::SocketBind => {
            if policy.socket_family != SocketFamily::Any
                && policy.socket_family != resource.socket_family
            {
                return None;
            }
            if policy.socket_transport != SocketTransport::Any
                && policy.socket_transport != resource.socket_transport
            {
                return None;
            }
            if policy.socket_port != 0 && policy.socket_port != resource.socket_port {
                return None;
            }
            if !matches_socket_ip(policy, resource.socket_family, &resource.socket_ip) {
                return None;
            }
        }
        PolicyAction::TaskSetNice => {}
    }

    let condition = match policy.attribute {
        StreamAttribute::Time => {
            if policy.modulo == 0 {
                return None;
            }
            let time_value = current_time % policy.modulo;
            matches_operator(policy.operator, time_value, policy.value)
        }
    };

    let entitlement = if condition {
        policy.entitlement
    } else {
        policy.entitlement.inverse()
    };

    Some(entitlement.decision())
}

fn matches_socket_ip(
    policy: &StreamPolicy,
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

pub(crate) fn evaluate_policies(
    current_subject: u32,
    current_action: PolicyAction,
    resource: &ResourceIdentity,
    current_time: u64,
) -> i32 {
    let mut decision = 0;
    let mut index = current_action.segment_start(STREAM_POLICY_SLOTS_PER_HOOK);
    let end = current_action.segment_end(STREAM_POLICY_SLOTS_PER_HOOK);

    while index < end && index < STREAM_POLICY_MAX_ENTRIES {
        if let Some(policy) = STREAM_POLICY.get(index) {
            if let Some(policy_decision) = evaluate_stream_policy(
                current_subject,
                current_action,
                resource,
                current_time,
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
pub fn evaluate_stream_policies(ctx: LsmContext) -> i32 {
    let current_decision = DECISIONS.get(0).copied().unwrap_or(0);
    let current_subject = ctx.uid();
    let resource = read_file_open_resource_identity(&ctx);
    let current_time = CURRENT_TIME.get(0).copied().unwrap_or(0);
    let stream_decision = evaluate_policies(
        current_subject,
        PolicyAction::FileOpen,
        &resource,
        current_time,
    );
    let decision = if current_decision != 0 || stream_decision != 0 {
        Entitlement::Deny.decision()
    } else {
        Entitlement::Permit.decision()
    };
    let _ = DECISIONS.set(0, decision, 0);

    unsafe {
        aya_ebpf::bpf_printk!(b"tails-pdp: evaluate_stream_policies");
        let _ = POLICY_JUMP_TABLE.tail_call(&ctx, COMBINE);
    }
    0
}

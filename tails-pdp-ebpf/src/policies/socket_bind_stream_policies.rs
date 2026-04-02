use tails_pdp_common::{
    ANY_SUBJECT, SOCKET_BIND_STREAM_POLICY_MAX_ENTRIES, SOCKET_IP_LEN, SocketBindStreamPolicy,
    SocketFamily, SocketTransport, StreamAttribute, StreamOperator,
};

use crate::{helpers::SocketBindResource, maps::SOCKET_BIND_STREAM_POLICIES};

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

    while index < SOCKET_BIND_STREAM_POLICY_MAX_ENTRIES {
        if let Some(policy) = SOCKET_BIND_STREAM_POLICIES.get(index) {
            if let Some(policy_decision) =
                evaluate_policy(current_subject, resource, current_time, policy)
            {
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

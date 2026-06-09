use aya_ebpf::{EbpfContext, macros::lsm, programs::LsmContext};
use tails_pdp_common::{
    AttributeKey, COMMAND_LEN, DEFAULT_DEFCON_LEVEL, Entitlement, MAX_ATTRIBUTE_CONDITIONS,
    POLICY_BANK_SIZE, SOCKET_IP_LEN, SocketBindStreamPolicy, SocketFamily, SocketTransport,
    attribute_bank, attribute_object_id, matches_attribute_condition, policy_bank_offset,
    socket_bind_stream_legacy_entitlement,
};

use crate::{
    helpers::{SocketBindResource, read_socket_bind_resource},
    maps::{
        ATTRIBUTE_GENERATION, ATTRIBUTES, CURRENT_DEFCON, CURRENT_TIME, CURRENT_TIME_ISO8601,
        SOCKET_BIND_JUMP_TABLE, SOCKET_BIND_STREAM_POLICIES, TAIL_IDX_SOCKET_BIND_COMBINE,
    },
    policies::decision::{DecisionMapExt, DecisionState},
};

pub(crate) fn evaluate_policies(
    current_subject: u32,
    current_command: &[u8; COMMAND_LEN],
    resource: &SocketBindResource,
    current_time: u64,
    current_iso8601_time: tails_pdp_common::Iso8601TimeParts,
    current_defcon: u32,
    generation: u32,
    attribute_bank: u32,
) -> DecisionState {
    let mut state = DecisionState::empty_for_generation(generation);
    let mut index = 0;
    let bank_offset = policy_bank_offset(generation);
    let mut matched_deny_index = u32::MAX;
    let mut matched_permit_index = u32::MAX;

    while index < POLICY_BANK_SIZE {
        let map_index = bank_offset + index;
        if let Some(policy) = SOCKET_BIND_STREAM_POLICIES.get(map_index) {
            if socket_bind_stream_policy_matches_request(
                policy,
                current_subject,
                current_command,
                resource,
            ) && (policy.attribute_condition_count == 0
                || attribute_conditions_match(
                    policy.attribute_condition_count,
                    &policy.attribute_conditions,
                    current_subject,
                    attribute_bank,
                ))
                && let Some(entitlement) = socket_bind_stream_legacy_entitlement(
                    current_time,
                    current_iso8601_time,
                    current_defcon,
                    policy,
                )
            {
                match entitlement {
                    Entitlement::Deny => {
                        if matched_deny_index == u32::MAX {
                            matched_deny_index = index;
                        }
                    }
                    Entitlement::Permit => {
                        if matched_permit_index == u32::MAX {
                            matched_permit_index = index;
                        }
                    }
                }
                state.record(entitlement);
                if state.deny != 0 && state.permit != 0 {
                    break;
                }
            }
        }
        index += 1;
    }

    crate::debug_printk!(
        b"sbsm deny=%d permit=%d didx=%d pidx=%d uid=%d t=%llu defcon=%d fam=%d tr=%d port=%d cmd=%s",
        state.deny,
        state.permit,
        matched_deny_index,
        matched_permit_index,
        current_subject,
        current_time,
        current_defcon,
        resource.family as u32,
        resource.transport as u32,
        resource.port as u32,
        current_command.as_ptr(),
    );

    state
}

fn socket_bind_stream_policy_matches_request(
    policy: &SocketBindStreamPolicy,
    current_subject: u32,
    current_command: &[u8; COMMAND_LEN],
    resource: &SocketBindResource,
) -> bool {
    if policy.enabled == 0 || policy.action != tails_pdp_common::PolicyAction::SocketBind {
        return false;
    }
    if policy.subject != tails_pdp_common::ANY_SUBJECT && policy.subject != current_subject {
        return false;
    }
    if !command_matches(&policy.command, current_command) {
        return false;
    }
    if policy.socket_family != SocketFamily::Any && policy.socket_family != resource.family {
        return false;
    }
    if policy.socket_transport != SocketTransport::Any
        && policy.socket_transport != resource.transport
    {
        return false;
    }
    if policy.socket_port != 0 && policy.socket_port != resource.port {
        return false;
    }
    socket_ip_matches(&policy.socket_ip, resource.family, &resource.ip)
}

fn command_matches(
    policy_command: &[u8; COMMAND_LEN],
    current_command: &[u8; COMMAND_LEN],
) -> bool {
    if policy_command[0] == 0 {
        return true;
    }

    let mut index = 0;
    while index < COMMAND_LEN {
        if policy_command[index] != current_command[index] {
            return false;
        }
        index += 1;
    }
    true
}

fn socket_ip_matches(
    policy_ip: &[u8; SOCKET_IP_LEN],
    family: SocketFamily,
    current_ip: &[u8; SOCKET_IP_LEN],
) -> bool {
    if ip_is_zero(policy_ip) {
        return true;
    }

    match family {
        SocketFamily::Inet => {
            policy_ip[0] == current_ip[0]
                && policy_ip[1] == current_ip[1]
                && policy_ip[2] == current_ip[2]
                && policy_ip[3] == current_ip[3]
        }
        SocketFamily::Inet6 => policy_ip == current_ip,
        SocketFamily::Any => false,
    }
}

fn ip_is_zero(ip: &[u8; SOCKET_IP_LEN]) -> bool {
    ip[0] == 0
        && ip[1] == 0
        && ip[2] == 0
        && ip[3] == 0
        && ip[4] == 0
        && ip[5] == 0
        && ip[6] == 0
        && ip[7] == 0
        && ip[8] == 0
        && ip[9] == 0
        && ip[10] == 0
        && ip[11] == 0
        && ip[12] == 0
        && ip[13] == 0
        && ip[14] == 0
        && ip[15] == 0
}

fn attribute_conditions_match(
    condition_count: u8,
    conditions: &[tails_pdp_common::AttributeCondition; MAX_ATTRIBUTE_CONDITIONS],
    current_subject: u32,
    bank: u32,
) -> bool {
    let mut index = 0;
    while index < MAX_ATTRIBUTE_CONDITIONS {
        if index >= condition_count as usize {
            return true;
        }
        let condition = &conditions[index];
        let key = AttributeKey::new(
            bank,
            condition.namespace,
            attribute_object_id(condition.namespace, current_subject),
            condition.name_hash,
        );
        let Some(value) = (unsafe { ATTRIBUTES.get(&key) }) else {
            return false;
        };
        if !matches_attribute_condition(condition, value) {
            return false;
        }
        index += 1;
    }
    true
}

#[lsm(hook = "socket_bind")]
pub fn evaluate_socket_bind_stream_policies(ctx: LsmContext) -> i32 {
    let mut current_state = DecisionState::from_map();
    let generation = current_state.generation;
    let current_subject = ctx.uid();
    let current_command = ctx.command().unwrap_or([0; COMMAND_LEN]);
    let resource = read_socket_bind_resource(&ctx);
    let current_time = CURRENT_TIME.get(0).copied().unwrap_or(0);
    let current_iso8601_time = CURRENT_TIME_ISO8601
        .get(0)
        .copied()
        .unwrap_or(tails_pdp_common::Iso8601TimeParts::new(1970, 1, 1, 0, 0, 0));
    let current_defcon = CURRENT_DEFCON
        .get(0)
        .copied()
        .unwrap_or(DEFAULT_DEFCON_LEVEL);
    let current_attribute_bank = attribute_bank(ATTRIBUTE_GENERATION.get(0).copied().unwrap_or(0));
    let stream_state = evaluate_policies(
        current_subject,
        &current_command,
        &resource,
        current_time,
        current_iso8601_time,
        current_defcon,
        generation,
        current_attribute_bank,
    );
    current_state.merge(stream_state);
    current_state.write_to_map();

    unsafe {
        let _ = SOCKET_BIND_JUMP_TABLE.tail_call(&ctx, TAIL_IDX_SOCKET_BIND_COMBINE);
    }

    0
}

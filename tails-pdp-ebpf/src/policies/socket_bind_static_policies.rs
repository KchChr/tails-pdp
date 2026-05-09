use aya_ebpf::{EbpfContext, macros::lsm, programs::LsmContext};
use tails_pdp_common::{
    Entitlement, POLICY_BANK_SIZE, SocketBindRequest, evaluate_socket_bind_static_policy,
    policy_bank_offset,
};

use crate::{
    helpers::{SocketBindResource, read_socket_bind_resource},
    maps::{SOCKET_BIND_JUMP_TABLE, SOCKET_BIND_STATIC_POLICIES, TAIL_IDX_SOCKET_BIND_STREAM},
    policies::decision::{DecisionMapExt, DecisionState, active_policy_generation},
};

pub(crate) fn evaluate_policies(
    current_subject: u32,
    resource: &SocketBindResource,
    generation: u32,
) -> DecisionState {
    let mut state = DecisionState::empty_for_generation(generation);
    let request = SocketBindRequest {
        subject: current_subject,
        socket_family: resource.family,
        socket_transport: resource.transport,
        socket_port: resource.port,
        socket_ip: resource.ip,
    };
    let mut index = 0;
    let bank_offset = policy_bank_offset(generation);
    let mut matched_deny_index = u32::MAX;
    let mut matched_permit_index = u32::MAX;

    while index < POLICY_BANK_SIZE {
        let map_index = bank_offset + index;
        if let Some(policy) = SOCKET_BIND_STATIC_POLICIES.get(map_index) {
            if let Some(entitlement) = evaluate_socket_bind_static_policy(&request, policy) {
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

    state
}

#[lsm(hook = "socket_bind")]
pub fn evaluate_socket_bind_static_policies(ctx: LsmContext) -> i32 {
    let subject = ctx.uid();
    let resource = read_socket_bind_resource(&ctx);
    let generation = active_policy_generation();
    let decision_state = evaluate_policies(subject, &resource, generation);
    decision_state.write_to_map();

    unsafe {
        let _ = SOCKET_BIND_JUMP_TABLE.tail_call(&ctx, TAIL_IDX_SOCKET_BIND_STREAM);
    }

    0
}

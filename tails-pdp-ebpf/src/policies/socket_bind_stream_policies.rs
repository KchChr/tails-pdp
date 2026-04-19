use aya_ebpf::{EbpfContext, macros::lsm, programs::LsmContext};
use tails_pdp_common::{
    Entitlement, SOCKET_BIND_STREAM_POLICY_MAX_ENTRIES, SocketBindRequest,
    evaluate_socket_bind_stream_policy,
};

use crate::{
    helpers::{SocketBindResource, read_socket_bind_resource},
    maps::{
        CURRENT_TIME, CURRENT_TIME_ISO8601, SOCKET_BIND_JUMP_TABLE, SOCKET_BIND_STREAM_POLICIES,
        TAIL_IDX_SOCKET_BIND_COMBINE,
    },
    policies::decision::{DecisionMapExt, DecisionState},
};

pub(crate) fn evaluate_policies(
    current_subject: u32,
    resource: &SocketBindResource,
    current_time: u64,
    current_iso8601_time: tails_pdp_common::Iso8601TimeParts,
) -> DecisionState {
    let mut state = DecisionState::empty();
    let request = SocketBindRequest {
        subject: current_subject,
        socket_family: resource.family,
        socket_transport: resource.transport,
        socket_port: resource.port,
        socket_ip: resource.ip,
    };
    let mut index = 0;
    let mut matched_deny_index = u32::MAX;
    let mut matched_permit_index = u32::MAX;

    while index < SOCKET_BIND_STREAM_POLICY_MAX_ENTRIES {
        if let Some(policy) = SOCKET_BIND_STREAM_POLICIES.get(index) {
            if let Some(entitlement) = evaluate_socket_bind_stream_policy(
                &request,
                current_time,
                current_iso8601_time,
                policy,
            ) {
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

    unsafe {
        aya_ebpf::bpf_printk!(
            b"sbsm deny=%d permit=%d didx=%d pidx=%d uid=%d t=%llu fam=%d tr=%d port=%d",
            state.deny,
            state.permit,
            matched_deny_index,
            matched_permit_index,
            current_subject,
            current_time,
            resource.family as u32,
            resource.transport as u32,
            resource.port as u32,
        );
    }

    state
}

#[lsm(hook = "socket_bind")]
pub fn evaluate_socket_bind_stream_policies(ctx: LsmContext) -> i32 {
    let mut current_state = DecisionState::from_map();
    let current_subject = ctx.uid();
    let resource = read_socket_bind_resource(&ctx);
    let current_time = CURRENT_TIME.get(0).copied().unwrap_or(0);
    let current_iso8601_time = CURRENT_TIME_ISO8601
        .get(0)
        .copied()
        .unwrap_or(tails_pdp_common::Iso8601TimeParts::new(1970, 1, 1, 0, 0, 0));
    let stream_state = evaluate_policies(
        current_subject,
        &resource,
        current_time,
        current_iso8601_time,
    );
    current_state.merge(stream_state);
    current_state.write_to_map();

    unsafe {
        let _ = SOCKET_BIND_JUMP_TABLE.tail_call(&ctx, TAIL_IDX_SOCKET_BIND_COMBINE);
    }

    0
}

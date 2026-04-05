use aya_ebpf::{EbpfContext, macros::lsm, programs::LsmContext};
use tails_pdp_common::{
    ANY_SUBJECT, Entitlement, FILE_OPEN_STREAM_POLICY_MAX_ENTRIES, FileOpenStreamPolicy,
    StreamAttribute, StreamOperator,
};

use crate::{
    helpers::{FileOpenResource, read_file_open_resource},
    maps::{
        CURRENT_TIME, DECISIONS, FILE_OPEN_JUMP_TABLE, FILE_OPEN_STREAM_POLICIES,
        TAIL_IDX_FILE_OPEN_COMBINE,
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

fn evaluate_policy(
    current_subject: u32,
    resource: &FileOpenResource,
    current_time: u64,
    policy: &FileOpenStreamPolicy,
) -> Option<i32> {
    if policy.enabled == 0 {
        return None;
    }
    if policy.subject != ANY_SUBJECT && policy.subject != current_subject {
        return None;
    }
    if !policy.matches_any_resource()
        && (policy.resource_device != resource.device || policy.resource_inode != resource.inode)
    {
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
    resource: &FileOpenResource,
    current_time: u64,
) -> i32 {
    let mut decision = 0;
    let mut index = 0;
    let mut matched_index = u32::MAX;

    while index < FILE_OPEN_STREAM_POLICY_MAX_ENTRIES {
        if let Some(policy) = FILE_OPEN_STREAM_POLICIES.get(index) {
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
            b"fosm res=%d idx=%d uid=%d t=%llu dev=%llu ino=%llu",
            decision as u32,
            matched_index,
            current_subject,
            current_time,
            resource.device,
            resource.inode,
        );
    }

    decision
}

#[lsm(hook = "file_open")]
pub fn evaluate_file_open_stream_policies(ctx: LsmContext) -> i32 {
    let current_decision = DECISIONS.get(0).copied().unwrap_or(0);
    let current_subject = ctx.uid();
    let resource = read_file_open_resource(&ctx);
    let current_time = CURRENT_TIME.get(0).copied().unwrap_or(0);
    let stream_decision = evaluate_policies(current_subject, &resource, current_time);
    let decision = if current_decision != 0 || stream_decision != 0 {
        Entitlement::Deny.decision()
    } else {
        Entitlement::Permit.decision()
    };
    let _ = DECISIONS.set(0, decision, 0);

    unsafe {
        let _ = FILE_OPEN_JUMP_TABLE.tail_call(&ctx, TAIL_IDX_FILE_OPEN_COMBINE);
    }
    0
}

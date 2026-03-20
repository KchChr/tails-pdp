use aya_ebpf::{macros::lsm, programs::LsmContext};
use tails_pdp_common::{Entitlement, PolicyAction, StreamAttribute, StreamOperator, StreamPolicy};

use crate::maps::{
    COMBINE, CURRENT_TIME, DECISIONS, POLICY_JUMP_TABLE, STREAM_POLICY, STREAM_POLICY_MAX_ENTRIES,
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
    current_action: PolicyAction,
    current_time: u64,
    policy: &StreamPolicy,
) -> Option<i32> {
    if policy.enabled == 0 {
        return None;
    }

    if policy.action != current_action {
        return None;
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

pub(crate) fn evaluate_policies(current_action: PolicyAction, current_time: u64) -> i32 {
    let mut decision = 0;
    let mut index = 0;

    while index < STREAM_POLICY_MAX_ENTRIES {
        if let Some(policy) = STREAM_POLICY.get(index) {
            if let Some(policy_decision) =
                evaluate_stream_policy(current_action, current_time, policy)
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

#[lsm(hook = "file_open")]
pub fn evaluate_stream_policies(ctx: LsmContext) -> i32 {
    let current_decision = DECISIONS.get(0).copied().unwrap_or(0);
    let current_time = CURRENT_TIME.get(0).copied().unwrap_or(0);
    let stream_decision = evaluate_policies(PolicyAction::FileOpen, current_time);
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

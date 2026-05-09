pub(crate) use tails_pdp_common::DecisionState;

use crate::maps::{
    DECISION_DENY_IDX, DECISION_GENERATION_IDX, DECISION_PERMIT_IDX, DECISIONS, POLICY_GENERATION,
};

pub(crate) trait DecisionMapExt {
    fn from_map() -> Self;
    fn write_to_map(self);
}

impl DecisionMapExt for DecisionState {
    fn from_map() -> Self {
        Self {
            deny: DECISIONS.get(DECISION_DENY_IDX).copied().unwrap_or(0),
            permit: DECISIONS.get(DECISION_PERMIT_IDX).copied().unwrap_or(0),
            generation: DECISIONS.get(DECISION_GENERATION_IDX).copied().unwrap_or(0),
        }
    }

    fn write_to_map(self) {
        if let Some(deny) = DECISIONS.get_ptr_mut(DECISION_DENY_IDX) {
            unsafe {
                *deny = self.deny;
            }
        }
        if let Some(permit) = DECISIONS.get_ptr_mut(DECISION_PERMIT_IDX) {
            unsafe {
                *permit = self.permit;
            }
        }
        if let Some(generation) = DECISIONS.get_ptr_mut(DECISION_GENERATION_IDX) {
            unsafe {
                *generation = self.generation;
            }
        }
    }
}

pub(crate) fn active_policy_generation() -> u32 {
    POLICY_GENERATION.get(0).copied().unwrap_or(0)
}

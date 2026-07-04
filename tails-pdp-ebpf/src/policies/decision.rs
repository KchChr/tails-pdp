pub(crate) use tails_pdp_common::DecisionState;

use crate::maps::{
    DECISION_DENY_IDX, DECISION_GENERATION_IDX, DECISION_PERMIT_IDX, DECISIONS, POLICY_GENERATION,
};

pub(crate) trait DecisionMapExt: Sized {
    fn from_map() -> Option<Self>;
    fn write_to_map(self) -> bool;
}

impl DecisionMapExt for DecisionState {
    fn from_map() -> Option<Self> {
        Some(Self {
            deny: DECISIONS.get(DECISION_DENY_IDX).copied()?,
            permit: DECISIONS.get(DECISION_PERMIT_IDX).copied()?,
            generation: DECISIONS.get(DECISION_GENERATION_IDX).copied()?,
        })
    }

    fn write_to_map(self) -> bool {
        let Some(deny) = DECISIONS.get_ptr_mut(DECISION_DENY_IDX) else {
            return false;
        };
        let Some(permit) = DECISIONS.get_ptr_mut(DECISION_PERMIT_IDX) else {
            return false;
        };
        let Some(generation) = DECISIONS.get_ptr_mut(DECISION_GENERATION_IDX) else {
            return false;
        };

        // SAFETY: each pointer comes from a distinct, fixed index in this CPU's PerCpuArray value.
        // The pointers are checked for absence above and do not escape this function.
        unsafe {
            *deny = self.deny;
            *permit = self.permit;
            *generation = self.generation;
        }
        true
    }
}

pub(crate) fn active_policy_generation() -> Option<u32> {
    POLICY_GENERATION.get(0).copied()
}

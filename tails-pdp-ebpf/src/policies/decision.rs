use tails_pdp_common::Entitlement;

use crate::maps::{DECISION_DENY_IDX, DECISION_PERMIT_IDX, DECISIONS};

#[derive(Copy, Clone)]
pub(crate) struct DecisionState {
    pub(crate) deny: u32,
    pub(crate) permit: u32,
}

impl DecisionState {
    pub(crate) const fn empty() -> Self {
        Self { deny: 0, permit: 0 }
    }

    pub(crate) fn from_map() -> Self {
        Self {
            deny: DECISIONS.get(DECISION_DENY_IDX).copied().unwrap_or(0),
            permit: DECISIONS.get(DECISION_PERMIT_IDX).copied().unwrap_or(0),
        }
    }

    pub(crate) fn write_to_map(self) {
        let _ = DECISIONS.set(DECISION_DENY_IDX, self.deny, 0);
        let _ = DECISIONS.set(DECISION_PERMIT_IDX, self.permit, 0);
    }

    pub(crate) fn record(&mut self, entitlement: Entitlement) {
        match entitlement {
            Entitlement::Deny => self.deny = 1,
            Entitlement::Permit => self.permit = 1,
        }
    }

    pub(crate) fn merge(&mut self, other: Self) {
        if other.deny != 0 {
            self.deny = 1;
        }
        if other.permit != 0 {
            self.permit = 1;
        }
    }
}

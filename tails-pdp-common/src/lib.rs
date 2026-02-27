#![no_std]

pub const POLICY_COUNT: usize = 3;

pub const TAIL_IDX_POLICY_1: u32 = 0;
pub const TAIL_IDX_POLICY_2: u32 = 1;
pub const TAIL_IDX_POLICY_3: u32 = 2;
pub const TAIL_IDX_COMBINER: u32 = 3;

pub const DECISION_INDETERMINATE: u8 = 0;
pub const DECISION_PERMIT: u8 = 1;
pub const DECISION_DENY: u8 = 2;

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct AuthorizationSubscription {
    pub request_id: u64,
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub gid: u32,
    pub file_ptr: u64,
    pub cred_ptr: u64,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct DecisionFlags {
    pub policy_1: u8,
    pub policy_2: u8,
    pub policy_3: u8,
}

impl DecisionFlags {
    pub const fn all_indeterminate() -> Self {
        Self {
            policy_1: DECISION_INDETERMINATE,
            policy_2: DECISION_INDETERMINATE,
            policy_3: DECISION_INDETERMINATE,
        }
    }

    pub const fn combine(&self) -> u8 {
        if self.policy_1 == DECISION_DENY
            || self.policy_2 == DECISION_DENY
            || self.policy_3 == DECISION_DENY
        {
            return DECISION_DENY;
        }

        if self.policy_1 == DECISION_PERMIT
            && self.policy_2 == DECISION_PERMIT
            && self.policy_3 == DECISION_PERMIT
        {
            return DECISION_PERMIT;
        }

        DECISION_INDETERMINATE
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for AuthorizationSubscription {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for DecisionFlags {}

use aya_ebpf::{macros::lsm, programs::LsmContext};
use tails_pdp_common::LSM_DENY;

use crate::policies::decision::{DecisionMapExt, DecisionState};

fn combine_decision() -> i32 {
    let Some(state) = DecisionState::from_map() else {
        return LSM_DENY;
    };
    state.lsm_return_value()
}

macro_rules! define_combine_program {
    ($fn_name:ident, $hook:literal, $deny_log:literal, $permit_log:literal) => {
        #[lsm(hook = $hook)]
        pub fn $fn_name(_ctx: LsmContext) -> i32 {
            let decision = combine_decision();
            if decision != 0 {
                crate::debug_printk!($deny_log);
            } else {
                crate::debug_printk!($permit_log);
            }
            decision
        }
    };
}

define_combine_program!(
    combine_file_open,
    "file_open",
    b"file_open final=deny",
    b"file_open final=permit"
);

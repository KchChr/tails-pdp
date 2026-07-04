use aya_ebpf::{EbpfContext, macros::lsm, programs::LsmContext};
use tails_pdp_common::{
    COMMAND_LEN, Entitlement, FileOpenRequest, LSM_DENY, POLICY_BANK_SIZE,
    evaluate_file_open_static_policy, policy_bank_offset,
};

use crate::{
    helpers::{FileOpenResource, read_file_open_resource},
    maps::{FILE_OPEN_JUMP_TABLE, FILE_OPEN_STATIC_POLICIES, TAIL_IDX_FILE_OPEN_STREAM},
    policies::decision::{DecisionMapExt, DecisionState, active_policy_generation},
};

pub(crate) fn evaluate_policies(
    current_subject: u32,
    current_command: &[u8; COMMAND_LEN],
    resource: &FileOpenResource,
    generation: u32,
) -> DecisionState {
    let mut state = DecisionState::empty_for_generation(generation);
    let request = FileOpenRequest {
        subject: current_subject,
        command: *current_command,
        resource_device: resource.device,
        resource_inode: resource.inode,
    };
    let mut index = 0;
    let bank_offset = policy_bank_offset(generation);
    let mut matched_deny_index = u32::MAX;
    let mut matched_permit_index = u32::MAX;

    while index < POLICY_BANK_SIZE {
        let map_index = bank_offset + index;
        if let Some(policy) = FILE_OPEN_STATIC_POLICIES.get(map_index) {
            if let Some(entitlement) = evaluate_file_open_static_policy(&request, policy) {
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
        b"fos deny=%d permit=%d didx=%d pidx=%d uid=%d dev=%llu ino=%llu cmd=%s",
        state.deny,
        state.permit,
        matched_deny_index,
        matched_permit_index,
        current_subject,
        resource.device,
        resource.inode,
        current_command.as_ptr(),
    );

    state
}

#[lsm(hook = "file_open")]
pub fn evaluate_file_open_static_policies(ctx: LsmContext) -> i32 {
    let subject = ctx.uid();
    let Ok(command) = ctx.command() else {
        return LSM_DENY;
    };
    let Some(resource) = read_file_open_resource(&ctx) else {
        return LSM_DENY;
    };
    let Some(generation) = active_policy_generation() else {
        return LSM_DENY;
    };
    let decision_state = evaluate_policies(subject, &command, &resource, generation);
    if !decision_state.write_to_map() {
        return LSM_DENY;
    }

    // SAFETY: the userspace loader installs the next LSM stage in this fixed slot. Reaching the
    // return below means the chain is incomplete, so access is denied.
    unsafe {
        let _ = FILE_OPEN_JUMP_TABLE.tail_call(&ctx, TAIL_IDX_FILE_OPEN_STREAM);
    }
    crate::debug_printk!(b"file_open tail_call=failed stage=stream");
    LSM_DENY
}

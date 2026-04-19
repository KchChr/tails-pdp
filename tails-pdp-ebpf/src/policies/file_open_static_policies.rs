use aya_ebpf::{EbpfContext, macros::lsm, programs::LsmContext};
use tails_pdp_common::{
    COMMAND_LEN, Entitlement, FILE_OPEN_STATIC_POLICY_MAX_ENTRIES, FileOpenRequest,
    evaluate_file_open_static_policy,
};

use crate::{
    helpers::{FileOpenResource, read_file_open_resource},
    maps::{FILE_OPEN_JUMP_TABLE, FILE_OPEN_STATIC_POLICIES, TAIL_IDX_FILE_OPEN_STREAM},
    policies::decision::{DecisionMapExt, DecisionState},
};

pub(crate) fn evaluate_policies(
    current_subject: u32,
    current_command: &[u8; COMMAND_LEN],
    resource: &FileOpenResource,
) -> DecisionState {
    let mut state = DecisionState::empty();
    let request = FileOpenRequest {
        subject: current_subject,
        command: *current_command,
        resource_device: resource.device,
        resource_inode: resource.inode,
    };
    let mut index = 0;
    let mut matched_deny_index = u32::MAX;
    let mut matched_permit_index = u32::MAX;

    while index < FILE_OPEN_STATIC_POLICY_MAX_ENTRIES {
        if let Some(policy) = FILE_OPEN_STATIC_POLICIES.get(index) {
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

    unsafe {
        aya_ebpf::bpf_printk!(
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
    }

    state
}

#[lsm(hook = "file_open")]
pub fn evaluate_file_open_static_policies(ctx: LsmContext) -> i32 {
    let subject = ctx.uid();
    let command = ctx.command().unwrap_or([0; COMMAND_LEN]);
    let resource = read_file_open_resource(&ctx);
    let decision_state = evaluate_policies(subject, &command, &resource);
    decision_state.write_to_map();

    unsafe {
        let _ = FILE_OPEN_JUMP_TABLE.tail_call(&ctx, TAIL_IDX_FILE_OPEN_STREAM);
    }

    0
}

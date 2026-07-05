use aya_ebpf::{EbpfContext, macros::lsm, programs::LsmContext};
use tails_pdp_common::{
    AttributeKey, COMMAND_LEN, Entitlement, FileOpenRequest, LSM_DENY, MAX_ATTRIBUTE_CONDITIONS,
    POLICY_BANK_SIZE, PolicyTime, attribute_bank, attribute_object_ids,
    file_open_stream_legacy_entitlement, file_open_stream_policy_applies_to_request,
    matches_attribute_condition, policy_bank_offset,
};

use crate::{
    helpers::{FileOpenResource, read_file_open_resource},
    maps::{
        ATTRIBUTE_GENERATION, ATTRIBUTES, CURRENT_TIME, FILE_OPEN_JUMP_TABLE,
        FILE_OPEN_STREAM_POLICIES, TAIL_IDX_FILE_OPEN_COMBINE,
    },
    policies::decision::{DecisionMapExt, DecisionState},
};

pub(crate) fn evaluate_policies(
    current_subject: u32,
    current_command: &[u8; COMMAND_LEN],
    resource: &FileOpenResource,
    current_time: PolicyTime,
    generation: u32,
    attribute_bank: u32,
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
        if let Some(policy) = FILE_OPEN_STREAM_POLICIES.get(map_index) {
            if file_open_stream_policy_applies_to_request(&request, policy)
                && attribute_conditions_match(
                    policy.attribute_condition_count,
                    &policy.attribute_conditions,
                    current_subject,
                    resource.device,
                    resource.inode,
                    attribute_bank,
                )
                && let Some(entitlement) = file_open_stream_legacy_entitlement(current_time, policy)
            {
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
        b"fosm deny=%d permit=%d didx=%d pidx=%d uid=%d t=%llu dev=%llu ino=%llu cmd=%s",
        state.deny,
        state.permit,
        matched_deny_index,
        matched_permit_index,
        current_subject,
        current_time.unix_seconds,
        resource.device,
        resource.inode,
        current_command.as_ptr(),
    );

    state
}

fn attribute_conditions_match(
    condition_count: u8,
    conditions: &[tails_pdp_common::AttributeCondition; MAX_ATTRIBUTE_CONDITIONS],
    current_subject: u32,
    resource_device: u64,
    resource_inode: u64,
    bank: u32,
) -> bool {
    let mut index = 0;
    while index < MAX_ATTRIBUTE_CONDITIONS {
        if index >= condition_count as usize {
            return true;
        }
        let condition = &conditions[index];
        let (object_id_primary, object_id_secondary) = attribute_object_ids(
            condition.namespace,
            current_subject,
            resource_device,
            resource_inode,
        );
        let key = AttributeKey::new(
            bank,
            condition.namespace,
            object_id_primary,
            object_id_secondary,
            condition.name_hash,
        );
        let Some(value) = (unsafe { ATTRIBUTES.get(&key) }) else {
            return false;
        };
        if !matches_attribute_condition(condition, value) {
            return false;
        }
        index += 1;
    }
    true
}

#[lsm(hook = "file_open")]
pub fn evaluate_file_open_stream_policies(ctx: LsmContext) -> i32 {
    let Some(mut current_state) = DecisionState::from_map() else {
        return LSM_DENY;
    };
    let generation = current_state.generation;
    let current_subject = ctx.uid();
    let Ok(current_command) = ctx.command() else {
        return LSM_DENY;
    };
    let Some(resource) = read_file_open_resource(&ctx) else {
        return LSM_DENY;
    };
    let Some(current_unix_time) = CURRENT_TIME.get(0).copied() else {
        return LSM_DENY;
    };
    let current_time = PolicyTime::from_unix_seconds(current_unix_time);
    let Some(attribute_generation) = ATTRIBUTE_GENERATION.get(0).copied() else {
        return LSM_DENY;
    };
    let current_attribute_bank = attribute_bank(attribute_generation);
    let stream_state = evaluate_policies(
        current_subject,
        &current_command,
        &resource,
        current_time,
        generation,
        current_attribute_bank,
    );
    current_state.merge(stream_state);
    if !current_state.write_to_map() {
        return LSM_DENY;
    }

    // SAFETY: the userspace loader installs the final LSM stage in this fixed slot. Reaching the
    // return below means the chain is incomplete, so access is denied.
    unsafe {
        let _ = FILE_OPEN_JUMP_TABLE.tail_call(&ctx, TAIL_IDX_FILE_OPEN_COMBINE);
    }
    crate::debug_printk!(b"file_open tail_call=failed stage=combine");
    LSM_DENY
}

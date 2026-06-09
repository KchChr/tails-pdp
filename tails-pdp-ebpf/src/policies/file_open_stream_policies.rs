use aya_ebpf::{EbpfContext, macros::lsm, programs::LsmContext};
use tails_pdp_common::{
    AttributeKey, COMMAND_LEN, DEFAULT_DEFCON_LEVEL, Entitlement, FileOpenRequest,
    MAX_ATTRIBUTE_CONDITIONS, POLICY_BANK_SIZE, attribute_bank, attribute_object_id,
    file_open_stream_legacy_entitlement, file_open_stream_policy_applies_to_request,
    matches_attribute_condition, policy_bank_offset,
};

use crate::{
    helpers::{FileOpenResource, read_file_open_resource},
    maps::{
        ATTRIBUTE_GENERATION, ATTRIBUTES, CURRENT_DEFCON, CURRENT_TIME, CURRENT_TIME_ISO8601,
        FILE_OPEN_JUMP_TABLE, FILE_OPEN_STREAM_POLICIES, TAIL_IDX_FILE_OPEN_COMBINE,
    },
    policies::decision::{DecisionMapExt, DecisionState},
};

pub(crate) fn evaluate_policies(
    current_subject: u32,
    current_command: &[u8; COMMAND_LEN],
    resource: &FileOpenResource,
    current_time: u64,
    current_iso8601_time: tails_pdp_common::Iso8601TimeParts,
    current_defcon: u32,
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
                    attribute_bank,
                )
                && let Some(entitlement) = file_open_stream_legacy_entitlement(
                    current_time,
                    current_iso8601_time,
                    current_defcon,
                    policy,
                )
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
        b"fosm deny=%d permit=%d didx=%d pidx=%d uid=%d t=%llu defcon=%d dev=%llu ino=%llu cmd=%s",
        state.deny,
        state.permit,
        matched_deny_index,
        matched_permit_index,
        current_subject,
        current_time,
        current_defcon,
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
    bank: u32,
) -> bool {
    let mut index = 0;
    while index < MAX_ATTRIBUTE_CONDITIONS {
        if index >= condition_count as usize {
            return true;
        }
        let condition = &conditions[index];
        let key = AttributeKey::new(
            bank,
            condition.namespace,
            attribute_object_id(condition.namespace, current_subject),
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
    let mut current_state = DecisionState::from_map();
    let generation = current_state.generation;
    let current_subject = ctx.uid();
    let current_command = ctx.command().unwrap_or([0; COMMAND_LEN]);
    let resource = read_file_open_resource(&ctx);
    let current_time = CURRENT_TIME.get(0).copied().unwrap_or(0);
    let current_iso8601_time = CURRENT_TIME_ISO8601
        .get(0)
        .copied()
        .unwrap_or(tails_pdp_common::Iso8601TimeParts::new(1970, 1, 1, 0, 0, 0));
    let current_defcon = CURRENT_DEFCON
        .get(0)
        .copied()
        .unwrap_or(DEFAULT_DEFCON_LEVEL);
    let current_attribute_bank = attribute_bank(ATTRIBUTE_GENERATION.get(0).copied().unwrap_or(0));
    let stream_state = evaluate_policies(
        current_subject,
        &current_command,
        &resource,
        current_time,
        current_iso8601_time,
        current_defcon,
        generation,
        current_attribute_bank,
    );
    current_state.merge(stream_state);
    current_state.write_to_map();

    unsafe {
        let _ = FILE_OPEN_JUMP_TABLE.tail_call(&ctx, TAIL_IDX_FILE_OPEN_COMBINE);
    }
    0
}

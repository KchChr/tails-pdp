use std::{mem::size_of, path::Path};

use anyhow::{Context, bail};
use aya::maps::{Array, MapInfo};
use tails_pdp_common::{
    POLICY_HOOKS, STATIC_POLICY_SLOTS_PER_HOOK, STREAM_POLICY_SLOTS_PER_HOOK, StaticPolicy,
    StreamPolicy,
};

use crate::BPF_PIN_DIRECTORY;

const ARRAY_KEY_SIZE: u32 = size_of::<u32>() as u32;
const STATIC_POLICY_MAX_ENTRIES: u32 =
    tails_pdp_common::POLICY_HOOK_COUNT * STATIC_POLICY_SLOTS_PER_HOOK;
const STREAM_POLICY_MAX_ENTRIES: u32 =
    tails_pdp_common::POLICY_HOOK_COUNT * STREAM_POLICY_SLOTS_PER_HOOK;
const CURRENT_TIME_MAX_ENTRIES: u32 = 1;

fn slot_for_static_policy(policy: StaticPolicy, local_index: u32) -> anyhow::Result<u32> {
    if local_index >= STATIC_POLICY_SLOTS_PER_HOOK {
        bail!(
            "too many STATIC_POLICY entries for hook {:?}: limit is {}",
            policy.action,
            STATIC_POLICY_SLOTS_PER_HOOK
        );
    }
    Ok(policy
        .action
        .local_slot(local_index, STATIC_POLICY_SLOTS_PER_HOOK))
}

fn slot_for_stream_policy(policy: StreamPolicy, local_index: u32) -> anyhow::Result<u32> {
    if local_index >= STREAM_POLICY_SLOTS_PER_HOOK {
        bail!(
            "too many STREAM_POLICY entries for hook {:?}: limit is {}",
            policy.action,
            STREAM_POLICY_SLOTS_PER_HOOK
        );
    }
    Ok(policy
        .action
        .local_slot(local_index, STREAM_POLICY_SLOTS_PER_HOOK))
}

fn verify_pinned_map_layout(
    map_name: &str,
    expected_value_size: u32,
    expected_max_entries: u32,
) -> anyhow::Result<()> {
    let pin_path = Path::new(BPF_PIN_DIRECTORY).join(map_name);
    if !pin_path.exists() {
        return Ok(());
    }

    let info = MapInfo::from_pin(&pin_path)
        .with_context(|| format!("failed to inspect pinned map '{}'", pin_path.display()))?;

    let actual_key_size = info.key_size();
    let actual_value_size = info.value_size();
    let actual_max_entries = info.max_entries();

    if actual_key_size == ARRAY_KEY_SIZE
        && actual_value_size == expected_value_size
        && actual_max_entries == expected_max_entries
    {
        return Ok(());
    }

    bail!(
        "pinned map '{}' at '{}' has an incompatible layout: expected key_size={}, value_size={}, max_entries={}, found key_size={}, value_size={}, max_entries={}. Remove the stale pinned map and restart, for example: sudo rm -f {}",
        map_name,
        pin_path.display(),
        ARRAY_KEY_SIZE,
        expected_value_size,
        expected_max_entries,
        actual_key_size,
        actual_value_size,
        actual_max_entries,
        pin_path.display(),
    );
}

pub fn verify_pinned_map_layouts() -> anyhow::Result<()> {
    verify_pinned_map_layout(
        "STATIC_POLICY",
        size_of::<StaticPolicy>() as u32,
        STATIC_POLICY_MAX_ENTRIES,
    )?;
    verify_pinned_map_layout(
        "STREAM_POLICY",
        size_of::<StreamPolicy>() as u32,
        STREAM_POLICY_MAX_ENTRIES,
    )?;
    verify_pinned_map_layout(
        "CURRENT_TIME",
        size_of::<u64>() as u32,
        CURRENT_TIME_MAX_ENTRIES,
    )?;
    Ok(())
}

pub fn load_static_policies(ebpf: &mut aya::Ebpf, policies: &[StaticPolicy]) -> anyhow::Result<()> {
    let mut static_policy: Array<_, StaticPolicy> = Array::try_from(
        ebpf.take_map("STATIC_POLICY")
            .context("map 'STATIC_POLICY' not found")?,
    )
    .context("failed to open STATIC_POLICY")?;

    for index in 0..static_policy.len() {
        static_policy
            .set(index, StaticPolicy::disabled(), 0)
            .with_context(|| format!("failed to clear STATIC_POLICY entry {index}"))?;
    }

    let mut next_index = [0u32; POLICY_HOOKS.len()];
    for policy in policies.iter().copied() {
        let policy = policy.resolve_resource_identity().with_context(|| {
            format!(
                "failed to resolve STATIC_POLICY entry for hook {:?} resource identity",
                policy.action
            )
        })?;
        let hook_slot = policy.action.hook_slot() as usize;
        let index = next_index[hook_slot];
        let slot = slot_for_static_policy(policy, index)?;
        static_policy.set(slot, policy, 0).with_context(|| {
            format!(
                "failed to write STATIC_POLICY hook {:?} local entry {index} (slot {slot})",
                policy.action
            )
        })?;
        next_index[hook_slot] += 1;
    }

    Ok(())
}

pub fn load_stream_policies(ebpf: &mut aya::Ebpf, policies: &[StreamPolicy]) -> anyhow::Result<()> {
    let mut stream_policy: Array<_, StreamPolicy> = Array::try_from(
        ebpf.take_map("STREAM_POLICY")
            .context("map 'STREAM_POLICY' not found")?,
    )
    .context("failed to open STREAM_POLICY")?;

    for index in 0..stream_policy.len() {
        stream_policy
            .set(index, StreamPolicy::disabled(), 0)
            .with_context(|| format!("failed to clear STREAM_POLICY entry {index}"))?;
    }

    let mut next_index = [0u32; POLICY_HOOKS.len()];
    for policy in policies.iter().copied() {
        let policy = policy.resolve_resource_identity().with_context(|| {
            format!(
                "failed to resolve STREAM_POLICY entry for hook {:?} resource identity",
                policy.action
            )
        })?;
        let hook_slot = policy.action.hook_slot() as usize;
        let index = next_index[hook_slot];
        let slot = slot_for_stream_policy(policy, index)?;
        stream_policy.set(slot, policy, 0).with_context(|| {
            format!(
                "failed to write STREAM_POLICY hook {:?} local entry {index} (slot {slot})",
                policy.action
            )
        })?;
        next_index[hook_slot] += 1;
    }

    Ok(())
}

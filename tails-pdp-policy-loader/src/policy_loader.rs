use std::{mem::size_of, path::Path};

use anyhow::{Context, bail};
use aya::maps::MapInfo;
use tails_pdp_common::{
    ATTRIBUTE_GENERATION_MAX_ENTRIES, ATTRIBUTE_MAP_MAX_ENTRIES, AttributeKey, AttributeValue,
    FILE_OPEN_STATIC_POLICY_MAX_ENTRIES, FILE_OPEN_STREAM_POLICY_MAX_ENTRIES, FileOpenStaticPolicy,
    FileOpenStreamPolicy, Iso8601TimeParts, POLICY_GENERATION_MAX_ENTRIES,
};
use tails_pdp_userspace_common::BPF_PIN_DIRECTORY;

const ARRAY_KEY_SIZE: u32 = size_of::<u32>() as u32;
const CURRENT_TIME_MAX_ENTRIES: u32 = 1;

fn verify_pinned_map_layout(
    map_name: &str,
    expected_key_size: u32,
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

    if actual_key_size == expected_key_size
        && actual_value_size == expected_value_size
        && actual_max_entries == expected_max_entries
    {
        return Ok(());
    }

    bail!(
        "pinned map '{}' at '{}' has an incompatible layout: expected key_size={}, value_size={}, max_entries={}, found key_size={}, value_size={}, max_entries={}. Remove the stale pinned map and restart, for example: sudo rm -f {}",
        map_name,
        pin_path.display(),
        expected_key_size,
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
        "FILE_OPEN_STATIC_POLICIES",
        ARRAY_KEY_SIZE,
        size_of::<FileOpenStaticPolicy>() as u32,
        FILE_OPEN_STATIC_POLICY_MAX_ENTRIES,
    )?;
    verify_pinned_map_layout(
        "FILE_OPEN_STREAM_POLICIES",
        ARRAY_KEY_SIZE,
        size_of::<FileOpenStreamPolicy>() as u32,
        FILE_OPEN_STREAM_POLICY_MAX_ENTRIES,
    )?;
    verify_pinned_map_layout(
        "POLICY_GENERATION",
        ARRAY_KEY_SIZE,
        size_of::<u32>() as u32,
        POLICY_GENERATION_MAX_ENTRIES,
    )?;
    verify_pinned_map_layout(
        "CURRENT_TIME",
        ARRAY_KEY_SIZE,
        size_of::<u64>() as u32,
        CURRENT_TIME_MAX_ENTRIES,
    )?;
    verify_pinned_map_layout(
        "CURRENT_TIME_ISO8601",
        ARRAY_KEY_SIZE,
        size_of::<Iso8601TimeParts>() as u32,
        CURRENT_TIME_MAX_ENTRIES,
    )?;
    verify_pinned_map_layout(
        "ATTRIBUTE_GENERATION",
        ARRAY_KEY_SIZE,
        size_of::<u32>() as u32,
        ATTRIBUTE_GENERATION_MAX_ENTRIES,
    )?;
    verify_pinned_map_layout(
        "ATTRIBUTES",
        size_of::<AttributeKey>() as u32,
        size_of::<AttributeValue>() as u32,
        ATTRIBUTE_MAP_MAX_ENTRIES,
    )?;
    Ok(())
}

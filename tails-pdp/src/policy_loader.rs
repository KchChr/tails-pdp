use std::{mem::size_of, path::Path};

use anyhow::{Context, bail};
use aya::maps::{Array, MapInfo};
use tails_pdp_common::{
    ATTRIBUTE_GENERATION_MAX_ENTRIES, ATTRIBUTE_MAP_MAX_ENTRIES, AttributeKey, AttributeValue,
    FILE_OPEN_STATIC_POLICY_MAX_ENTRIES, FILE_OPEN_STREAM_POLICY_MAX_ENTRIES, FileOpenStaticPolicy,
    FileOpenStreamPolicy, Iso8601TimeParts, POLICY_GENERATION_MAX_ENTRIES,
    SOCKET_BIND_STATIC_POLICY_MAX_ENTRIES, SOCKET_BIND_STREAM_POLICY_MAX_ENTRIES,
    STREAM_ATTRIBUTE_MAX_ENTRIES, SocketBindStaticPolicy, SocketBindStreamPolicy,
};

use crate::BPF_PIN_DIRECTORY;

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
        "SOCKET_BIND_STATIC_POLICIES",
        ARRAY_KEY_SIZE,
        size_of::<SocketBindStaticPolicy>() as u32,
        SOCKET_BIND_STATIC_POLICY_MAX_ENTRIES,
    )?;
    verify_pinned_map_layout(
        "SOCKET_BIND_STREAM_POLICIES",
        ARRAY_KEY_SIZE,
        size_of::<SocketBindStreamPolicy>() as u32,
        SOCKET_BIND_STREAM_POLICY_MAX_ENTRIES,
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
        "CURRENT_DEFCON",
        ARRAY_KEY_SIZE,
        size_of::<u32>() as u32,
        STREAM_ATTRIBUTE_MAX_ENTRIES,
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

pub fn load_file_open_static_policies(
    ebpf: &mut aya::Ebpf,
    policies: &[FileOpenStaticPolicy],
) -> anyhow::Result<()> {
    let mut map: Array<_, FileOpenStaticPolicy> = Array::try_from(
        ebpf.take_map("FILE_OPEN_STATIC_POLICIES")
            .context("map 'FILE_OPEN_STATIC_POLICIES' not found")?,
    )
    .context("failed to open FILE_OPEN_STATIC_POLICIES")?;

    for index in 0..map.len() {
        map.set(index, FileOpenStaticPolicy::disabled(), 0)
            .with_context(|| format!("failed to clear FILE_OPEN_STATIC_POLICIES[{index}]"))?;
    }

    if policies.len() > map.len() as usize {
        bail!(
            "too many file_open static policies: {} > {}",
            policies.len(),
            map.len()
        );
    }

    for (index, policy) in policies.iter().copied().enumerate() {
        let policy = policy.resolve_resource_identity().with_context(|| {
            format!("failed to resolve FILE_OPEN_STATIC_POLICIES[{index}] resource identity")
        })?;
        map.set(index as u32, policy, 0)
            .with_context(|| format!("failed to write FILE_OPEN_STATIC_POLICIES[{index}]"))?;
    }

    Ok(())
}

pub fn load_file_open_stream_policies(
    ebpf: &mut aya::Ebpf,
    policies: &[FileOpenStreamPolicy],
) -> anyhow::Result<()> {
    let mut map: Array<_, FileOpenStreamPolicy> = Array::try_from(
        ebpf.take_map("FILE_OPEN_STREAM_POLICIES")
            .context("map 'FILE_OPEN_STREAM_POLICIES' not found")?,
    )
    .context("failed to open FILE_OPEN_STREAM_POLICIES")?;

    for index in 0..map.len() {
        map.set(index, FileOpenStreamPolicy::disabled(), 0)
            .with_context(|| format!("failed to clear FILE_OPEN_STREAM_POLICIES[{index}]"))?;
    }

    if policies.len() > map.len() as usize {
        bail!(
            "too many file_open stream policies: {} > {}",
            policies.len(),
            map.len()
        );
    }

    for (index, policy) in policies.iter().copied().enumerate() {
        let policy = policy.resolve_resource_identity().with_context(|| {
            format!("failed to resolve FILE_OPEN_STREAM_POLICIES[{index}] resource identity")
        })?;
        map.set(index as u32, policy, 0)
            .with_context(|| format!("failed to write FILE_OPEN_STREAM_POLICIES[{index}]"))?;
    }

    Ok(())
}

pub fn load_socket_bind_static_policies(
    ebpf: &mut aya::Ebpf,
    policies: &[SocketBindStaticPolicy],
) -> anyhow::Result<()> {
    let mut map: Array<_, SocketBindStaticPolicy> = Array::try_from(
        ebpf.take_map("SOCKET_BIND_STATIC_POLICIES")
            .context("map 'SOCKET_BIND_STATIC_POLICIES' not found")?,
    )
    .context("failed to open SOCKET_BIND_STATIC_POLICIES")?;

    for index in 0..map.len() {
        map.set(index, SocketBindStaticPolicy::disabled(), 0)
            .with_context(|| format!("failed to clear SOCKET_BIND_STATIC_POLICIES[{index}]"))?;
    }

    if policies.len() > map.len() as usize {
        bail!(
            "too many socket_bind static policies: {} > {}",
            policies.len(),
            map.len()
        );
    }

    for (index, policy) in policies.iter().copied().enumerate() {
        let policy = policy.resolve_resource_identity().with_context(|| {
            format!("failed to resolve SOCKET_BIND_STATIC_POLICIES[{index}] resource identity")
        })?;
        map.set(index as u32, policy, 0)
            .with_context(|| format!("failed to write SOCKET_BIND_STATIC_POLICIES[{index}]"))?;
    }

    Ok(())
}

pub fn load_socket_bind_stream_policies(
    ebpf: &mut aya::Ebpf,
    policies: &[SocketBindStreamPolicy],
) -> anyhow::Result<()> {
    let mut map: Array<_, SocketBindStreamPolicy> = Array::try_from(
        ebpf.take_map("SOCKET_BIND_STREAM_POLICIES")
            .context("map 'SOCKET_BIND_STREAM_POLICIES' not found")?,
    )
    .context("failed to open SOCKET_BIND_STREAM_POLICIES")?;

    for index in 0..map.len() {
        map.set(index, SocketBindStreamPolicy::disabled(), 0)
            .with_context(|| format!("failed to clear SOCKET_BIND_STREAM_POLICIES[{index}]"))?;
    }

    if policies.len() > map.len() as usize {
        bail!(
            "too many socket_bind stream policies: {} > {}",
            policies.len(),
            map.len()
        );
    }

    for (index, policy) in policies.iter().copied().enumerate() {
        let policy = policy.resolve_resource_identity().with_context(|| {
            format!("failed to resolve SOCKET_BIND_STREAM_POLICIES[{index}] resource identity")
        })?;
        map.set(index as u32, policy, 0)
            .with_context(|| format!("failed to write SOCKET_BIND_STREAM_POLICIES[{index}]"))?;
    }

    Ok(())
}

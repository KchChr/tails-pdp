use anyhow::Context;
use tails_pdp_common::{
    FileOpenStaticPolicy, FileOpenStreamPolicy, POLICY_BANK_SIZE, SocketBindStaticPolicy,
    SocketBindStreamPolicy, StreamAttribute,
};

use crate::maps::{
    FileOpenStaticPolicyMap, FileOpenStreamPolicyMap, SocketBindStaticPolicyMap,
    SocketBindStreamPolicyMap,
};

fn fixed_string(bytes: &[u8]) -> String {
    let len = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..len]).into_owned()
}

pub fn show_file_open_static(
    map: &FileOpenStaticPolicyMap,
    bank_offset: u32,
    active_only: bool,
) -> anyhow::Result<()> {
    println!("FILE_OPEN_STATIC_POLICIES:");
    for index in 0..POLICY_BANK_SIZE {
        let map_index = bank_offset + index;
        let policy: FileOpenStaticPolicy = map
            .get(&map_index, 0)
            .with_context(|| format!("failed to read FILE_OPEN_STATIC_POLICIES[{map_index}]"))?;
        if active_only && policy.enabled == 0 {
            continue;
        }
        println!(
            "[{index}] enabled={} entitlement={:?} action={:?} subject={} command={:?} resource={:?} device={} inode={}",
            policy.enabled,
            policy.entitlement,
            policy.action,
            policy.subject,
            fixed_string(&policy.command),
            fixed_string(&policy.resource),
            policy.resource_device,
            policy.resource_inode,
        );
    }
    println!();
    Ok(())
}

pub fn show_file_open_stream(
    map: &FileOpenStreamPolicyMap,
    bank_offset: u32,
    active_only: bool,
) -> anyhow::Result<()> {
    println!("FILE_OPEN_STREAM_POLICIES:");
    for index in 0..POLICY_BANK_SIZE {
        let map_index = bank_offset + index;
        let policy: FileOpenStreamPolicy = map
            .get(&map_index, 0)
            .with_context(|| format!("failed to read FILE_OPEN_STREAM_POLICIES[{map_index}]"))?;
        if active_only && policy.enabled == 0 {
            continue;
        }
        if policy.attribute == StreamAttribute::Time {
            println!(
                "[{index}] enabled={} entitlement={:?} action={:?} subject={} resource={:?} device={} inode={} attribute={:?} operator={:?} modulo={} value={}",
                policy.enabled,
                policy.entitlement,
                policy.action,
                policy.subject,
                fixed_string(&policy.resource),
                policy.resource_device,
                policy.resource_inode,
                policy.attribute,
                policy.operator,
                policy.modulo,
                policy.value,
            );
        } else {
            println!(
                "[{index}] enabled={} entitlement={:?} action={:?} subject={} resource={:?} device={} inode={} attribute={:?} operator={:?} value={}",
                policy.enabled,
                policy.entitlement,
                policy.action,
                policy.subject,
                fixed_string(&policy.resource),
                policy.resource_device,
                policy.resource_inode,
                policy.attribute,
                policy.operator,
                policy.value,
            );
        }
    }
    println!();
    Ok(())
}

pub fn show_socket_bind_static(
    map: &SocketBindStaticPolicyMap,
    bank_offset: u32,
    active_only: bool,
) -> anyhow::Result<()> {
    println!("SOCKET_BIND_STATIC_POLICIES:");
    for index in 0..POLICY_BANK_SIZE {
        let map_index = bank_offset + index;
        let policy: SocketBindStaticPolicy = map
            .get(&map_index, 0)
            .with_context(|| format!("failed to read SOCKET_BIND_STATIC_POLICIES[{map_index}]"))?;
        if active_only && policy.enabled == 0 {
            continue;
        }
        println!(
            "[{index}] enabled={} entitlement={:?} action={:?} subject={} family={:?} transport={:?} port={} resource={:?}",
            policy.enabled,
            policy.entitlement,
            policy.action,
            policy.subject,
            policy.socket_family,
            policy.socket_transport,
            policy.socket_port,
            fixed_string(&policy.resource),
        );
    }
    println!();
    Ok(())
}

pub fn show_socket_bind_stream(
    map: &SocketBindStreamPolicyMap,
    bank_offset: u32,
    active_only: bool,
) -> anyhow::Result<()> {
    println!("SOCKET_BIND_STREAM_POLICIES:");
    for index in 0..POLICY_BANK_SIZE {
        let map_index = bank_offset + index;
        let policy: SocketBindStreamPolicy = map
            .get(&map_index, 0)
            .with_context(|| format!("failed to read SOCKET_BIND_STREAM_POLICIES[{map_index}]"))?;
        if active_only && policy.enabled == 0 {
            continue;
        }
        if policy.attribute == StreamAttribute::Time {
            println!(
                "[{index}] enabled={} entitlement={:?} action={:?} subject={} family={:?} transport={:?} port={} resource={:?} attribute={:?} operator={:?} modulo={} value={}",
                policy.enabled,
                policy.entitlement,
                policy.action,
                policy.subject,
                policy.socket_family,
                policy.socket_transport,
                policy.socket_port,
                fixed_string(&policy.resource),
                policy.attribute,
                policy.operator,
                policy.modulo,
                policy.value,
            );
        } else {
            println!(
                "[{index}] enabled={} entitlement={:?} action={:?} subject={} family={:?} transport={:?} port={} resource={:?} attribute={:?} operator={:?} value={}",
                policy.enabled,
                policy.entitlement,
                policy.action,
                policy.subject,
                policy.socket_family,
                policy.socket_transport,
                policy.socket_port,
                fixed_string(&policy.resource),
                policy.attribute,
                policy.operator,
                policy.value,
            );
        }
    }
    Ok(())
}

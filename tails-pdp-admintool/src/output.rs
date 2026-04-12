use anyhow::Context;
use tails_pdp_common::{
    FileOpenStaticPolicy, FileOpenStreamPolicy, SocketBindStaticPolicy, SocketBindStreamPolicy,
    StreamAttribute,
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
    active_only: bool,
) -> anyhow::Result<()> {
    println!("FILE_OPEN_STATIC_POLICIES:");
    for index in 0..map.len() {
        let policy: FileOpenStaticPolicy = map
            .get(&index, 0)
            .with_context(|| format!("failed to read FILE_OPEN_STATIC_POLICIES[{index}]"))?;
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
    active_only: bool,
) -> anyhow::Result<()> {
    println!("FILE_OPEN_STREAM_POLICIES:");
    for index in 0..map.len() {
        let policy: FileOpenStreamPolicy = map
            .get(&index, 0)
            .with_context(|| format!("failed to read FILE_OPEN_STREAM_POLICIES[{index}]"))?;
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
    active_only: bool,
) -> anyhow::Result<()> {
    println!("SOCKET_BIND_STATIC_POLICIES:");
    for index in 0..map.len() {
        let policy: SocketBindStaticPolicy = map
            .get(&index, 0)
            .with_context(|| format!("failed to read SOCKET_BIND_STATIC_POLICIES[{index}]"))?;
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
    active_only: bool,
) -> anyhow::Result<()> {
    println!("SOCKET_BIND_STREAM_POLICIES:");
    for index in 0..map.len() {
        let policy: SocketBindStreamPolicy = map
            .get(&index, 0)
            .with_context(|| format!("failed to read SOCKET_BIND_STREAM_POLICIES[{index}]"))?;
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

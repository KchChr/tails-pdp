use anyhow::Context;
use tails_pdp_common::{StaticPolicy, StreamPolicy};

use crate::maps::{StaticPolicyMap, StreamPolicyMap};

fn fixed_string(bytes: &[u8]) -> String {
    let len = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..len]).into_owned()
}

pub fn show_static(map: &StaticPolicyMap, active_only: bool) -> anyhow::Result<()> {
    println!("STATIC_POLICY:");
    for index in 0..map.len() {
        let policy: StaticPolicy = map
            .get(&index, 0)
            .with_context(|| format!("failed to read STATIC_POLICY[{index}]"))?;
        if active_only && policy.enabled == 0 {
            continue;
        }

        let command = fixed_string(&policy.command);
        let resource = fixed_string(&policy.resource);
        println!(
            "[{index}] enabled={} entitlement={:?} action={:?} subject={} command={:?} resource={:?} device={} inode={}",
            policy.enabled,
            policy.entitlement,
            policy.action,
            policy.subject,
            command,
            resource,
            policy.resource_device,
            policy.resource_inode,
        );
    }
    println!();
    Ok(())
}

pub fn show_stream(map: &StreamPolicyMap, active_only: bool) -> anyhow::Result<()> {
    println!("STREAM_POLICY:");
    for index in 0..map.len() {
        let policy: StreamPolicy = map
            .get(&index, 0)
            .with_context(|| format!("failed to read STREAM_POLICY[{index}]"))?;
        if active_only && policy.enabled == 0 {
            continue;
        }

        let resource = fixed_string(&policy.resource);
        println!(
            "[{index}] enabled={} entitlement={:?} action={:?} subject={} resource={:?} device={} inode={} attribute={:?} operator={:?} modulo={} value={}",
            policy.enabled,
            policy.entitlement,
            policy.action,
            policy.subject,
            resource,
            policy.resource_device,
            policy.resource_inode,
            policy.attribute,
            policy.operator,
            policy.modulo,
            policy.value,
        );
    }
    Ok(())
}

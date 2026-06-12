use std::collections::HashMap;

use anyhow::Context;
use tails_pdp_common::{
    AttributeCondition, AttributeHash, AttributeKey, AttributeNamespace, AttributeValue,
    AttributeValueKind, FileOpenStaticPolicy, FileOpenStreamPolicy, MAX_ATTRIBUTE_CONDITIONS,
    POLICY_BANK_SIZE, StreamAttribute,
};

use crate::maps::{AttributeMap, FileOpenStaticPolicyMap, FileOpenStreamPolicyMap};

pub type HashDictionary = HashMap<(u64, u64), String>;

fn fixed_string(bytes: &[u8]) -> String {
    let len = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..len]).into_owned()
}

fn hash_key(hash: AttributeHash) -> (u64, u64) {
    (hash.low, hash.high)
}

fn describe_hash(hash: AttributeHash, dictionary: &HashDictionary) -> String {
    dictionary
        .get(&hash_key(hash))
        .cloned()
        .unwrap_or_else(|| format!("hash({:016x}{:016x})", hash.high, hash.low))
}

fn namespace_prefix(namespace: AttributeNamespace) -> &'static str {
    match namespace {
        AttributeNamespace::System => "system",
        AttributeNamespace::Subject => "subject",
        AttributeNamespace::Resource => "resource",
    }
}

fn describe_condition(condition: &AttributeCondition, dictionary: &HashDictionary) -> String {
    let name = describe_hash(condition.name_hash, dictionary);
    let value = match condition.value_kind {
        AttributeValueKind::Number => condition.value_number.to_string(),
        AttributeValueKind::Bool => match condition.value_number {
            0 => String::from("false"),
            _ => String::from("true"),
        },
        AttributeValueKind::String => {
            format!("{:?}", describe_hash(condition.value_hash, dictionary))
        }
    };

    format!(
        "{}.{} {:?} {}",
        namespace_prefix(condition.namespace),
        name,
        condition.operator,
        value
    )
}

fn describe_value(value: AttributeValue, dictionary: &HashDictionary) -> String {
    match value.kind {
        AttributeValueKind::Number => value.number.to_string(),
        AttributeValueKind::Bool => match value.number {
            0 => String::from("false"),
            _ => String::from("true"),
        },
        AttributeValueKind::String => format!("{:?}", describe_hash(value.hash, dictionary)),
    }
}

fn subject_label(subject: u32) -> String {
    if subject == tails_pdp_common::ANY_SUBJECT {
        String::from("any")
    } else {
        subject.to_string()
    }
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
            "[{index}] enabled={} entitlement={:?} subject={} command={:?} resource={:?} device={} inode={}",
            policy.enabled,
            policy.entitlement,
            subject_label(policy.subject),
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
    dictionary: &HashDictionary,
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

        let legacy_condition = if policy.stream_condition_enabled == 0 {
            String::from("none")
        } else if policy.attribute == StreamAttribute::Time {
            format!(
                "{:?} % {} {:?} {}",
                policy.attribute, policy.modulo, policy.operator, policy.value
            )
        } else {
            format!(
                "{:?} {:?} {}",
                policy.attribute, policy.operator, policy.value
            )
        };

        println!(
            "[{index}] enabled={} entitlement={:?} subject={} command={:?} resource={:?} device={} inode={} legacy_condition={}",
            policy.enabled,
            policy.entitlement,
            subject_label(policy.subject),
            fixed_string(&policy.command),
            fixed_string(&policy.resource),
            policy.resource_device,
            policy.resource_inode,
            legacy_condition,
        );

        let condition_count =
            (policy.attribute_condition_count as usize).min(MAX_ATTRIBUTE_CONDITIONS);
        for condition in policy.attribute_conditions.iter().take(condition_count) {
            println!(
                "    attribute_condition={}",
                describe_condition(condition, dictionary)
            );
        }
    }
    println!();
    Ok(())
}

pub fn show_attributes(
    attributes: &AttributeMap,
    bank: u32,
    dictionary: &HashDictionary,
) -> anyhow::Result<()> {
    println!("ATTRIBUTES:");
    let mut rows = Vec::new();
    for key in attributes.keys() {
        let key: AttributeKey = key.context("failed to iterate ATTRIBUTES keys")?;
        if key.bank != bank {
            continue;
        }
        let value = attributes
            .get(&key, 0)
            .with_context(|| "failed to read ATTRIBUTES value")?;
        rows.push((key, value));
    }

    rows.sort_by_key(|(key, _)| {
        (
            key.namespace as u8,
            key.object_id_primary,
            key.object_id_secondary,
            key.name_hash.high,
            key.name_hash.low,
        )
    });

    for (key, value) in rows {
        let name = describe_hash(key.name_hash, dictionary);
        let value = describe_value(value, dictionary);
        match key.namespace {
            AttributeNamespace::System => {
                println!("system.{name} = {value}");
            }
            AttributeNamespace::Subject => {
                println!("subject:{} subject.{name} = {value}", key.object_id_primary);
            }
            AttributeNamespace::Resource => {
                println!(
                    "resource:{}:{} resource.{name} = {value}",
                    key.object_id_primary, key.object_id_secondary
                );
            }
        }
    }
    println!();
    Ok(())
}

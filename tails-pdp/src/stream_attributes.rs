use std::{
    env, fs,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

use anyhow::{Context, bail};
use aya::maps::{Array, HashMap as AyaHashMap, MapData};
use log::{info, warn};
use tails_pdp_common::{
    AttributeKey, AttributeNamespace, AttributeValue, AttributeValueKind, DEFAULT_DEFCON_LEVEL,
    DEFCON_MAX_LEVEL, DEFCON_MIN_LEVEL, attribute_bank, attribute_hash, encode_kernel_dev_t,
};
use tokio::time::{Duration, sleep};

use crate::fs_watch;

const STREAM_ATTRIBUTES_DIRECTORY_NAME: &str = "attributes";
const ATTRIBUTE_FILE_EXTENSION: &str = "attributes";
const SYSTEM_ATTRIBUTES_FILE_NAME: &str = "system.attributes";
const SUBJECT_ATTRIBUTES_DIRECTORY_NAME: &str = "subjects";
const RESOURCE_ATTRIBUTES_DIRECTORY_NAME: &str = "resources";
const STREAM_ATTRIBUTE_EVENT_DEBOUNCE: Duration = Duration::from_millis(100);

pub type AttributeMap = AyaHashMap<MapData, AttributeKey, AttributeValue>;
pub type AttributeGenerationMap = Array<MapData, u32>;

pub struct AttributeMaps {
    attributes: AttributeMap,
    generation: AttributeGenerationMap,
}

#[derive(Clone, Eq, PartialEq)]
struct ParsedAttribute {
    namespace: AttributeNamespace,
    object_id_primary: u64,
    object_id_secondary: u64,
    name_hash: tails_pdp_common::AttributeHash,
    value: AttributeValue,
}

pub fn default_stream_attributes_directory() -> anyhow::Result<PathBuf> {
    Ok(env::current_dir()
        .context("failed to determine current working directory")?
        .join(STREAM_ATTRIBUTES_DIRECTORY_NAME))
}

pub fn open_attribute_maps(ebpf: &mut aya::Ebpf) -> anyhow::Result<AttributeMaps> {
    let attributes = AyaHashMap::try_from(
        ebpf.take_map("ATTRIBUTES")
            .context("map 'ATTRIBUTES' not found")?,
    )
    .context("failed to open ATTRIBUTES")?;
    let generation = Array::try_from(
        ebpf.take_map("ATTRIBUTE_GENERATION")
            .context("map 'ATTRIBUTE_GENERATION' not found")?,
    )
    .context("failed to open ATTRIBUTE_GENERATION")?;

    Ok(AttributeMaps {
        attributes,
        generation,
    })
}

pub fn write_current_attributes(attribute_maps: &mut AttributeMaps) -> anyhow::Result<()> {
    let directory = ensure_attribute_directory()?;
    let attributes = read_attribute_directory(&directory)?;
    commit_attributes(attribute_maps, &attributes)
}

pub async fn run_attribute_updater(attribute_maps: &mut AttributeMaps) -> anyhow::Result<()> {
    let directory = ensure_attribute_directory()?;
    let mut watcher = fs_watch::watch_directory_recursive(&directory)?;
    let mut last_applied = None;

    apply_attribute_directory(&directory, attribute_maps, &mut last_applied)?;

    loop {
        watcher.wait_for_change().await?;
        sleep(STREAM_ATTRIBUTE_EVENT_DEBOUNCE).await;
        apply_attribute_directory(&directory, attribute_maps, &mut last_applied)?;
    }
}

fn ensure_attribute_directory() -> anyhow::Result<PathBuf> {
    let directory = default_stream_attributes_directory()?;
    fs::create_dir_all(&directory).with_context(|| {
        format!(
            "failed to create stream attributes directory '{}'",
            directory.display()
        )
    })?;
    fs::create_dir_all(directory.join(SUBJECT_ATTRIBUTES_DIRECTORY_NAME)).with_context(|| {
        format!(
            "failed to create subject attributes directory '{}'",
            directory.join(SUBJECT_ATTRIBUTES_DIRECTORY_NAME).display()
        )
    })?;
    fs::create_dir_all(directory.join(RESOURCE_ATTRIBUTES_DIRECTORY_NAME)).with_context(|| {
        format!(
            "failed to create resource attributes directory '{}'",
            directory.join(RESOURCE_ATTRIBUTES_DIRECTORY_NAME).display()
        )
    })?;

    let system_path = directory.join(SYSTEM_ATTRIBUTES_FILE_NAME);
    if !system_path.exists() {
        fs::write(&system_path, format!("defcon = {DEFAULT_DEFCON_LEVEL}\n")).with_context(
            || {
                format!(
                    "failed to create default system attributes file '{}'",
                    system_path.display()
                )
            },
        )?;
    }

    info!("Watching stream attributes '{}'", directory.display());
    Ok(directory)
}

fn apply_attribute_directory(
    directory: &Path,
    attribute_maps: &mut AttributeMaps,
    last_applied: &mut Option<Vec<ParsedAttribute>>,
) -> anyhow::Result<()> {
    match read_attribute_directory(directory) {
        Ok(attributes) if last_applied.as_ref() != Some(&attributes) => {
            commit_attributes(attribute_maps, &attributes)?;
            *last_applied = Some(attributes);
        }
        Ok(_) => {}
        Err(error) => {
            warn!(
                "Ignoring invalid stream attributes directory '{}': {error:#}",
                directory.display()
            );
        }
    }

    Ok(())
}

fn read_attribute_directory(directory: &Path) -> anyhow::Result<Vec<ParsedAttribute>> {
    let mut attributes = Vec::new();
    let system_path = directory.join(SYSTEM_ATTRIBUTES_FILE_NAME);
    if system_path.exists() {
        read_attribute_file(
            &system_path,
            AttributeNamespace::System,
            0,
            0,
            &mut attributes,
        )?;
    }

    let subjects_directory = directory.join(SUBJECT_ATTRIBUTES_DIRECTORY_NAME);
    if subjects_directory.exists() {
        let mut entries = fs::read_dir(&subjects_directory)
            .with_context(|| format!("failed to read '{}'", subjects_directory.display()))?
            .collect::<Result<Vec<_>, _>>()
            .with_context(|| format!("failed to iterate '{}'", subjects_directory.display()))?;
        entries.sort_by_key(|entry| entry.path());

        for entry in entries {
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some(ATTRIBUTE_FILE_EXTENSION) {
                continue;
            }
            let uid = path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .context("subject attribute file has no valid UTF-8 stem")?
                .parse::<u64>()
                .with_context(|| {
                    format!(
                        "subject attribute file '{}' must be named '<uid>.attributes'",
                        path.display()
                    )
                })?;
            read_attribute_file(&path, AttributeNamespace::Subject, uid, 0, &mut attributes)?;
        }
    }

    let resources_directory = directory.join(RESOURCE_ATTRIBUTES_DIRECTORY_NAME);
    if resources_directory.exists() {
        read_resource_attributes_recursive(
            &resources_directory,
            &resources_directory,
            &mut attributes,
        )?;
    }

    sort_attributes(&mut attributes);
    ensure_unique_attributes(&attributes)?;
    Ok(attributes)
}

fn read_resource_attributes_recursive(
    root: &Path,
    current: &Path,
    attributes: &mut Vec<ParsedAttribute>,
) -> anyhow::Result<()> {
    let mut entries = fs::read_dir(current)
        .with_context(|| format!("failed to read '{}'", current.display()))?
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("failed to iterate '{}'", current.display()))?;
    entries.sort_by_key(|entry| entry.path());

    for entry in entries {
        let path = entry.path();
        if path.is_dir() {
            read_resource_attributes_recursive(root, &path, attributes)?;
            continue;
        }
        if path.extension().and_then(|ext| ext.to_str()) != Some(ATTRIBUTE_FILE_EXTENSION) {
            continue;
        }

        let mut relative_resource_path = path
            .strip_prefix(root)
            .with_context(|| {
                format!(
                    "failed to create resource-relative path for '{}'",
                    path.display()
                )
            })?
            .to_path_buf();
        relative_resource_path.set_extension("");
        let resource_path = Path::new("/").join(&relative_resource_path);
        let metadata = fs::metadata(&resource_path).with_context(|| {
            format!(
                "resource attribute file '{}' refers to missing resource '{}'",
                path.display(),
                resource_path.display()
            )
        })?;
        let resource_device = encode_kernel_dev_t(metadata.dev());
        let resource_inode = metadata.ino();
        read_attribute_file(
            &path,
            AttributeNamespace::Resource,
            resource_device,
            resource_inode,
            attributes,
        )?;
    }

    Ok(())
}

fn read_attribute_file(
    path: &Path,
    namespace: AttributeNamespace,
    object_id_primary: u64,
    object_id_secondary: u64,
    attributes: &mut Vec<ParsedAttribute>,
) -> anyhow::Result<()> {
    let source =
        fs::read_to_string(path).with_context(|| format!("failed to read '{}'", path.display()))?;

    for (line_no, line) in source.lines().enumerate() {
        let line_no = line_no + 1;
        let statement = line
            .split_once('#')
            .map(|(before_comment, _)| before_comment)
            .unwrap_or(line)
            .trim();
        if statement.is_empty() {
            continue;
        }

        let (name, raw_value) = statement.split_once('=').ok_or_else(|| {
            anyhow::anyhow!(
                "{}:{}: expected '<attribute> = <value>'",
                path.display(),
                line_no
            )
        })?;
        let name = name.trim();
        validate_attribute_name(name)
            .with_context(|| format!("{}:{}: invalid attribute name", path.display(), line_no))?;
        let value = parse_attribute_value(raw_value.trim())
            .with_context(|| format!("{}:{}: invalid attribute value", path.display(), line_no))?;
        validate_system_defcon_attribute(namespace, name, &value).with_context(|| {
            format!(
                "{}:{}: invalid system DEFCON attribute",
                path.display(),
                line_no
            )
        })?;

        attributes.push(ParsedAttribute {
            namespace,
            object_id_primary,
            object_id_secondary,
            name_hash: attribute_hash(name),
            value,
        });
    }

    Ok(())
}

fn validate_attribute_name(name: &str) -> anyhow::Result<()> {
    if name.is_empty() {
        bail!("attribute name must not be empty");
    }
    if !name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        bail!("attribute name '{name}' contains unsupported characters");
    }
    Ok(())
}

fn parse_attribute_value(raw: &str) -> anyhow::Result<AttributeValue> {
    if raw.starts_with('"') || raw.ends_with('"') {
        if !raw.starts_with('"') || !raw.ends_with('"') || raw.len() < 2 {
            bail!("invalid quoted string '{raw}'");
        }
        return Ok(AttributeValue::string(attribute_hash(
            &raw[1..raw.len() - 1],
        )));
    }

    match raw {
        "true" => return Ok(AttributeValue::bool(true)),
        "false" => return Ok(AttributeValue::bool(false)),
        _ => {}
    }

    let number = raw
        .parse::<u64>()
        .with_context(|| format!("value '{raw}' is not a number, bool, or quoted string"))?;
    Ok(AttributeValue::number(number))
}

fn validate_system_defcon_attribute(
    namespace: AttributeNamespace,
    name: &str,
    value: &AttributeValue,
) -> anyhow::Result<()> {
    if namespace != AttributeNamespace::System || name != "defcon" {
        return Ok(());
    }
    if value.kind != AttributeValueKind::Number {
        bail!("system.defcon must be a number");
    }
    if !(DEFCON_MIN_LEVEL as u64..=DEFCON_MAX_LEVEL as u64).contains(&value.number) {
        bail!(
            "system.defcon value {} is outside {}..={}",
            value.number,
            DEFCON_MIN_LEVEL,
            DEFCON_MAX_LEVEL
        );
    }
    Ok(())
}

fn sort_attributes(attributes: &mut [ParsedAttribute]) {
    attributes.sort_by_key(|attribute| {
        (
            attribute.namespace as u8,
            attribute.object_id_primary,
            attribute.object_id_secondary,
            attribute.name_hash.low,
            attribute.name_hash.high,
        )
    });
}

fn ensure_unique_attributes(attributes: &[ParsedAttribute]) -> anyhow::Result<()> {
    for window in attributes.windows(2) {
        if window[0].namespace == window[1].namespace
            && window[0].object_id_primary == window[1].object_id_primary
            && window[0].object_id_secondary == window[1].object_id_secondary
            && window[0].name_hash == window[1].name_hash
        {
            bail!("duplicate stream attribute definition");
        }
    }
    Ok(())
}

fn commit_attributes(
    attribute_maps: &mut AttributeMaps,
    attributes: &[ParsedAttribute],
) -> anyhow::Result<()> {
    let current_generation = attribute_maps.generation.get(&0, 0).unwrap_or(0);
    let next_generation = current_generation.wrapping_add(1);
    let bank = attribute_bank(next_generation);

    clear_attribute_bank(&mut attribute_maps.attributes, bank)?;

    for attribute in attributes {
        let key = AttributeKey::new(
            bank,
            attribute.namespace,
            attribute.object_id_primary,
            attribute.object_id_secondary,
            attribute.name_hash,
        );
        attribute_maps
            .attributes
            .insert(key, attribute.value, 0)
            .with_context(|| {
                format!(
                    "failed to write ATTRIBUTES bank={} namespace={:?} object_id_primary={} object_id_secondary={}",
                    bank,
                    attribute.namespace,
                    attribute.object_id_primary,
                    attribute.object_id_secondary
                )
            })?;
    }

    attribute_maps
        .generation
        .set(0, next_generation, 0)
        .context("failed to commit ATTRIBUTE_GENERATION[0]")?;
    info!(
        "Stream attributes committed generation={} count={}",
        next_generation,
        attributes.len()
    );

    Ok(())
}

fn clear_attribute_bank(attributes: &mut AttributeMap, bank: u32) -> anyhow::Result<()> {
    let mut keys = Vec::new();
    for key in attributes.keys() {
        let key = key.context("failed to iterate ATTRIBUTES keys")?;
        if key.bank == bank {
            keys.push(key);
        }
    }

    for key in keys {
        attributes
            .remove(&key)
            .context("failed to remove stale ATTRIBUTES entry")?;
    }

    Ok(())
}

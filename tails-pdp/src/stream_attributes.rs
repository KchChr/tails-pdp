use std::{
    env, fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, bail};
use aya::maps::{Array, HashMap as AyaHashMap, MapData};
use log::{info, warn};
use tails_pdp_common::{
    AttributeKey, AttributeNamespace, AttributeValue, DEFAULT_DEFCON_LEVEL, DEFCON_MAX_LEVEL,
    DEFCON_MIN_LEVEL, attribute_bank, attribute_hash,
};
use tokio::time::{Duration, sleep};

use crate::fs_watch;

const STREAM_ATTRIBUTES_DIRECTORY_NAME: &str = "environment";
const DEFCON_FILE_NAME: &str = "DEFCON.txt";
const SYSTEM_ATTRIBUTES_FILE_NAME: &str = "system.env";
const SUBJECT_ATTRIBUTES_DIRECTORY_NAME: &str = "subjects";
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
    object_id: u64,
    name_hash: tails_pdp_common::AttributeHash,
    value: AttributeValue,
}

pub fn default_stream_attributes_directory() -> anyhow::Result<PathBuf> {
    Ok(env::current_dir()
        .context("failed to determine current working directory")?
        .join(STREAM_ATTRIBUTES_DIRECTORY_NAME))
}

pub fn open_current_defcon_map(ebpf: &mut aya::Ebpf) -> anyhow::Result<Array<MapData, u32>> {
    Array::try_from(
        ebpf.take_map("CURRENT_DEFCON")
            .context("map 'CURRENT_DEFCON' not found")?,
    )
    .context("failed to open CURRENT_DEFCON")
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

pub fn write_current_defcon(current_defcon: &mut Array<MapData, u32>) -> anyhow::Result<()> {
    let defcon_path = ensure_defcon_file()?;
    let mut last_applied = None;
    apply_defcon_file(&defcon_path, current_defcon, &mut last_applied)
}

pub fn write_current_attributes(attribute_maps: &mut AttributeMaps) -> anyhow::Result<()> {
    let directory = ensure_attribute_environment()?;
    let attributes = read_attribute_environment(&directory)?;
    commit_attributes(attribute_maps, &attributes)
}

pub async fn run_defcon_updater(current_defcon: &mut Array<MapData, u32>) -> anyhow::Result<()> {
    let defcon_path = ensure_defcon_file()?;
    let directory = defcon_path
        .parent()
        .context("DEFCON path has no parent directory")?;
    let mut watcher = fs_watch::watch_directory(directory)?;
    let mut last_applied = None;

    apply_defcon_file(&defcon_path, current_defcon, &mut last_applied)?;

    loop {
        watcher.wait_for_change().await?;
        sleep(STREAM_ATTRIBUTE_EVENT_DEBOUNCE).await;
        apply_defcon_file(&defcon_path, current_defcon, &mut last_applied)?;
    }
}

pub async fn run_attribute_updater(attribute_maps: &mut AttributeMaps) -> anyhow::Result<()> {
    let directory = ensure_attribute_environment()?;
    let mut watcher = fs_watch::watch_directory_recursive(&directory)?;
    let mut last_applied = None;

    apply_attribute_environment(&directory, attribute_maps, &mut last_applied)?;

    loop {
        watcher.wait_for_change().await?;
        sleep(STREAM_ATTRIBUTE_EVENT_DEBOUNCE).await;
        apply_attribute_environment(&directory, attribute_maps, &mut last_applied)?;
    }
}

fn ensure_defcon_file() -> anyhow::Result<PathBuf> {
    let directory = default_stream_attributes_directory()?;
    fs::create_dir_all(&directory).with_context(|| {
        format!(
            "failed to create stream attributes directory '{}'",
            directory.display()
        )
    })?;

    let defcon_path = directory.join(DEFCON_FILE_NAME);
    if !defcon_path.exists() {
        fs::write(&defcon_path, format!("{DEFAULT_DEFCON_LEVEL}\n")).with_context(|| {
            format!(
                "failed to create default DEFCON file '{}'",
                defcon_path.display()
            )
        })?;
    }

    info!(
        "Watching DEFCON stream attribute '{}'",
        defcon_path.display()
    );
    Ok(defcon_path)
}

fn ensure_attribute_environment() -> anyhow::Result<PathBuf> {
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

fn apply_defcon_file(
    defcon_path: &Path,
    current_defcon: &mut Array<MapData, u32>,
    last_applied: &mut Option<u32>,
) -> anyhow::Result<()> {
    match read_defcon_level(defcon_path) {
        Ok(level) if Some(level) != *last_applied => {
            current_defcon
                .set(0, level, 0)
                .context("failed to write CURRENT_DEFCON[0]")?;
            *last_applied = Some(level);
            info!("DEFCON stream attribute set to {level}");
        }
        Ok(_) => {}
        Err(error) => {
            if last_applied.is_none() {
                current_defcon
                    .set(0, DEFAULT_DEFCON_LEVEL, 0)
                    .context("failed to write default CURRENT_DEFCON[0]")?;
                *last_applied = Some(DEFAULT_DEFCON_LEVEL);
            }
            warn!(
                "Ignoring invalid DEFCON stream attribute '{}': {error:#}",
                defcon_path.display()
            );
        }
    }

    Ok(())
}

fn apply_attribute_environment(
    directory: &Path,
    attribute_maps: &mut AttributeMaps,
    last_applied: &mut Option<Vec<ParsedAttribute>>,
) -> anyhow::Result<()> {
    match read_attribute_environment(directory) {
        Ok(attributes) if last_applied.as_ref() != Some(&attributes) => {
            commit_attributes(attribute_maps, &attributes)?;
            *last_applied = Some(attributes);
        }
        Ok(_) => {}
        Err(error) => {
            warn!(
                "Ignoring invalid stream attribute environment '{}': {error:#}",
                directory.display()
            );
        }
    }

    Ok(())
}

fn read_attribute_environment(directory: &Path) -> anyhow::Result<Vec<ParsedAttribute>> {
    let mut attributes = Vec::new();
    let system_path = directory.join(SYSTEM_ATTRIBUTES_FILE_NAME);
    if system_path.exists() {
        read_env_file(&system_path, AttributeNamespace::System, 0, &mut attributes)?;
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
            if path.extension().and_then(|ext| ext.to_str()) != Some("env") {
                continue;
            }
            let uid = path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .context("subject attribute file has no valid UTF-8 stem")?
                .parse::<u64>()
                .with_context(|| {
                    format!(
                        "subject attribute file '{}' must be named '<uid>.env'",
                        path.display()
                    )
                })?;
            read_env_file(&path, AttributeNamespace::Subject, uid, &mut attributes)?;
        }
    }

    sort_attributes(&mut attributes);
    ensure_unique_attributes(&attributes)?;
    Ok(attributes)
}

fn read_env_file(
    path: &Path,
    namespace: AttributeNamespace,
    object_id: u64,
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

        attributes.push(ParsedAttribute {
            namespace,
            object_id,
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

fn sort_attributes(attributes: &mut [ParsedAttribute]) {
    attributes.sort_by_key(|attribute| {
        (
            attribute.namespace as u8,
            attribute.object_id,
            attribute.name_hash.low,
            attribute.name_hash.high,
        )
    });
}

fn ensure_unique_attributes(attributes: &[ParsedAttribute]) -> anyhow::Result<()> {
    for window in attributes.windows(2) {
        if window[0].namespace == window[1].namespace
            && window[0].object_id == window[1].object_id
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
            attribute.object_id,
            attribute.name_hash,
        );
        attribute_maps
            .attributes
            .insert(key, attribute.value, 0)
            .with_context(|| {
                format!(
                    "failed to write ATTRIBUTES bank={} namespace={:?} object_id={}",
                    bank, attribute.namespace, attribute.object_id
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

fn read_defcon_level(defcon_path: &Path) -> anyhow::Result<u32> {
    let raw = fs::read_to_string(defcon_path)
        .with_context(|| format!("failed to read '{}'", defcon_path.display()))?;
    let trimmed = raw.trim();
    let level: u32 = trimmed
        .parse()
        .with_context(|| format!("DEFCON value '{trimmed}' is not an integer"))?;

    if !(DEFCON_MIN_LEVEL..=DEFCON_MAX_LEVEL).contains(&level) {
        bail!("DEFCON value {level} is outside {DEFCON_MIN_LEVEL}..={DEFCON_MAX_LEVEL}");
    }

    Ok(level)
}

use std::path::PathBuf;

use anyhow::Context;
use aya::maps::{Array, HashMap as AyaHashMap, Map, MapData};
use tails_pdp_common::{AttributeKey, AttributeValue, FileOpenStaticPolicy, FileOpenStreamPolicy};

pub type FileOpenStaticPolicyMap = Array<MapData, FileOpenStaticPolicy>;
pub type FileOpenStreamPolicyMap = Array<MapData, FileOpenStreamPolicy>;
pub type PolicyGenerationMap = Array<MapData, u32>;
pub type AttributeGenerationMap = Array<MapData, u32>;
pub type AttributeMap = AyaHashMap<MapData, AttributeKey, AttributeValue>;

fn open_array_map<T: aya::Pod>(path: &PathBuf, label: &str) -> anyhow::Result<Array<MapData, T>> {
    let map_data = MapData::from_pin(path)
        .with_context(|| format!("failed to open pinned map at {}", path.display()))?;
    let map = Map::Array(map_data);
    Array::try_from(map).with_context(|| format!("failed to treat pinned map as {label}"))
}

fn open_hash_map<K: aya::Pod, V: aya::Pod>(
    path: &PathBuf,
    label: &str,
) -> anyhow::Result<AyaHashMap<MapData, K, V>> {
    let map_data = MapData::from_pin(path)
        .with_context(|| format!("failed to open pinned map at {}", path.display()))?;
    let map = Map::HashMap(map_data);
    AyaHashMap::try_from(map).with_context(|| format!("failed to treat pinned map as {label}"))
}

pub fn open_file_open_static_policies(path: &PathBuf) -> anyhow::Result<FileOpenStaticPolicyMap> {
    open_array_map(path, "Array<FileOpenStaticPolicy>")
}

pub fn open_file_open_stream_policies(path: &PathBuf) -> anyhow::Result<FileOpenStreamPolicyMap> {
    open_array_map(path, "Array<FileOpenStreamPolicy>")
}

pub fn open_policy_generation(path: &PathBuf) -> anyhow::Result<PolicyGenerationMap> {
    open_array_map(path, "Array<u32>")
}

pub fn open_attribute_generation(path: &PathBuf) -> anyhow::Result<AttributeGenerationMap> {
    open_array_map(path, "Array<u32>")
}

pub fn open_attributes(path: &PathBuf) -> anyhow::Result<AttributeMap> {
    open_hash_map(path, "HashMap<AttributeKey, AttributeValue>")
}

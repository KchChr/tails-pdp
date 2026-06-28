use std::path::{Path, PathBuf};

use anyhow::Context;
use aya::{
    Pod,
    maps::{Array, HashMap, Map, MapData},
};

pub mod fs_watch;

pub const BPF_PIN_DIRECTORY: &str = "/sys/fs/bpf/tails-pdp";

pub fn pinned_map_path(map_name: &str) -> PathBuf {
    Path::new(BPF_PIN_DIRECTORY).join(map_name)
}

pub fn open_pinned_array<T: Pod>(map_name: &str) -> anyhow::Result<Array<MapData, T>> {
    let pin_path = pinned_map_path(map_name);
    let map_data = MapData::from_pin(&pin_path)
        .with_context(|| format!("failed to open pinned map '{}'", pin_path.display()))?;
    Array::try_from(Map::Array(map_data))
        .with_context(|| format!("failed to open {map_name} as array map"))
}

pub fn open_pinned_hash_map<K: Pod, V: Pod>(
    map_name: &str,
) -> anyhow::Result<HashMap<MapData, K, V>> {
    let pin_path = pinned_map_path(map_name);
    let map_data = MapData::from_pin(&pin_path)
        .with_context(|| format!("failed to open pinned map '{}'", pin_path.display()))?;
    HashMap::try_from(Map::HashMap(map_data))
        .with_context(|| format!("failed to open {map_name} as hash map"))
}

use std::path::PathBuf;

use anyhow::Context;
use aya::maps::{Array, Map, MapData};
use tails_pdp_common::{StaticPolicy, StreamPolicy};

pub type StaticPolicyMap = Array<MapData, StaticPolicy>;
pub type StreamPolicyMap = Array<MapData, StreamPolicy>;

pub fn open_static_policy(path: &PathBuf) -> anyhow::Result<StaticPolicyMap> {
    let map_data = MapData::from_pin(path)
        .with_context(|| format!("failed to open pinned map at {}", path.display()))?;
    let map = Map::Array(map_data);
    Array::try_from(map).context("failed to treat pinned map as Array<StaticPolicy>")
}

pub fn open_stream_policy(path: &PathBuf) -> anyhow::Result<StreamPolicyMap> {
    let map_data = MapData::from_pin(path)
        .with_context(|| format!("failed to open pinned map at {}", path.display()))?;
    let map = Map::Array(map_data);
    Array::try_from(map).context("failed to treat pinned map as Array<StreamPolicy>")
}

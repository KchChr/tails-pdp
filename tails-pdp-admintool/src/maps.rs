use std::path::PathBuf;

use anyhow::Context;
use aya::maps::{Array, Map, MapData};
use tails_pdp_common::{
    FileOpenStaticPolicy, FileOpenStreamPolicy, SocketBindStaticPolicy, SocketBindStreamPolicy,
};

pub type FileOpenStaticPolicyMap = Array<MapData, FileOpenStaticPolicy>;
pub type FileOpenStreamPolicyMap = Array<MapData, FileOpenStreamPolicy>;
pub type SocketBindStaticPolicyMap = Array<MapData, SocketBindStaticPolicy>;
pub type SocketBindStreamPolicyMap = Array<MapData, SocketBindStreamPolicy>;
pub type PolicyGenerationMap = Array<MapData, u32>;

fn open_array_map<T: aya::Pod>(path: &PathBuf, label: &str) -> anyhow::Result<Array<MapData, T>> {
    let map_data = MapData::from_pin(path)
        .with_context(|| format!("failed to open pinned map at {}", path.display()))?;
    let map = Map::Array(map_data);
    Array::try_from(map).with_context(|| format!("failed to treat pinned map as {label}"))
}

pub fn open_file_open_static_policies(path: &PathBuf) -> anyhow::Result<FileOpenStaticPolicyMap> {
    open_array_map(path, "Array<FileOpenStaticPolicy>")
}

pub fn open_file_open_stream_policies(path: &PathBuf) -> anyhow::Result<FileOpenStreamPolicyMap> {
    open_array_map(path, "Array<FileOpenStreamPolicy>")
}

pub fn open_socket_bind_static_policies(
    path: &PathBuf,
) -> anyhow::Result<SocketBindStaticPolicyMap> {
    open_array_map(path, "Array<SocketBindStaticPolicy>")
}

pub fn open_socket_bind_stream_policies(
    path: &PathBuf,
) -> anyhow::Result<SocketBindStreamPolicyMap> {
    open_array_map(path, "Array<SocketBindStreamPolicy>")
}

pub fn open_policy_generation(path: &PathBuf) -> anyhow::Result<PolicyGenerationMap> {
    open_array_map(path, "Array<u32>")
}

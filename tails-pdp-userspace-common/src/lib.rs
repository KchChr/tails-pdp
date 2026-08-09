use std::path::{Path, PathBuf};

use anyhow::Context;
use aya::{
    Pod,
    maps::{Array, HashMap, Map, MapData},
};
use tokio::sync::mpsc;

pub mod fs_watch;

/// A successfully activated state that requires the userspace PEP to re-evaluate open files.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EnforcementTrigger {
    PolicyGenerationActivated { generation: u32 },
    AttributeGenerationActivated { generation: u32 },
    TimeConditionChanged { unix_seconds: u64 },
}

pub const ENFORCEMENT_TRIGGER_CHANNEL_CAPACITY: usize = 1;

/// Queues a re-evaluation request without allowing unbounded update backlogs.
///
/// A full channel already represents a pending re-evaluation. Dropping the newer notification is
/// safe because the PEP reads the active map generations at the beginning of its next scan.
pub fn notify_enforcement(
    sender: &mpsc::Sender<EnforcementTrigger>,
    trigger: EnforcementTrigger,
) -> anyhow::Result<bool> {
    match sender.try_send(trigger) {
        Ok(()) => Ok(true),
        Err(mpsc::error::TrySendError::Full(_)) => Ok(false),
        Err(mpsc::error::TrySendError::Closed(_)) => {
            anyhow::bail!("userspace PEP trigger channel is closed")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_trigger_channel_coalesces_without_growing() {
        let (sender, mut receiver) = mpsc::channel(ENFORCEMENT_TRIGGER_CHANNEL_CAPACITY);
        assert!(
            notify_enforcement(
                &sender,
                EnforcementTrigger::PolicyGenerationActivated { generation: 1 }
            )
            .expect("first trigger")
        );
        assert!(
            !notify_enforcement(
                &sender,
                EnforcementTrigger::AttributeGenerationActivated { generation: 2 }
            )
            .expect("full channel is coalesced")
        );
        assert_eq!(
            receiver.try_recv().expect("queued trigger"),
            EnforcementTrigger::PolicyGenerationActivated { generation: 1 }
        );
        assert!(receiver.try_recv().is_err());
    }

    #[test]
    fn closed_trigger_channel_is_an_error() {
        let (sender, receiver) = mpsc::channel(ENFORCEMENT_TRIGGER_CHANNEL_CAPACITY);
        drop(receiver);
        assert!(
            notify_enforcement(
                &sender,
                EnforcementTrigger::PolicyGenerationActivated { generation: 1 }
            )
            .is_err()
        );
    }
}

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

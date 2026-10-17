//! Gemeinsame Linux-Infrastruktur für Loader, Administration und Userspace-PEP.
//!
//! Map-Helfer verwenden [`BPF_PIN_DIRECTORY`]. [`fs_watch`] beobachtet relevante
//! Dateiveröffentlichungen und Löschungen; [`timing`] liefert optionale Messmarkierungen.
//! [`EnforcementTrigger`] transportiert Aktivierungs- und Zeitursachen. Der begrenzte
//! Kanal bündelt ausstehende Aktivierungen; er ist kein verlustfreies Ereignisjournal.

use std::path::{Path, PathBuf};

use anyhow::Context;
use aya::{
    Pod,
    maps::{Array, HashMap, Map, MapData},
};
use tokio::sync::mpsc;

/// Asynchroner Linux-Inotify-Watcher für dateibasierte Konfigurationsveröffentlichung.
pub mod fs_watch;
/// Opt-in Monotonzeitmarkierungen für die instrumentierte Evaluation.
pub mod timing;

/// A successfully activated state that requires the userspace PEP to re-evaluate open files.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EnforcementTrigger {
    /// Eine neue Policygeneration ist nach vollständigem Schreiben aktiv.
    PolicyGenerationActivated {
        /// Nach Bankwechsel aktive Policygeneration.
        generation: u32,
    },
    /// Eine neue Attributgeneration ist nach vollständigem Schreiben aktiv.
    AttributeGenerationActivated {
        /// Nach Bankwechsel aktive Attributgeneration.
        generation: u32,
    },
    /// Eine vom PEP berechnete relevante Zeitgrenze wurde erreicht.
    TimeConditionChanged {
        /// Unix-Sekunden der geplanten Zeitgrenze.
        unix_seconds: u64,
    },
}

/// Ein ausstehender Aktivierungstrigger genügt, weil der Scan den aktuellen Zustand liest.
pub const ENFORCEMENT_TRIGGER_CHANNEL_CAPACITY: usize = 1;

/// Queues a re-evaluation request without allowing unbounded update backlogs.
///
/// A full channel already represents a pending re-evaluation. Dropping the newer notification is
/// safe because the PEP reads the active map generations at the beginning of its next scan.
///
/// # Rückgabe und Fehler
///
/// `Ok(true)` reiht den Trigger ein; `Ok(false)` bündelt ihn mit einer bereits
/// ausstehenden Aktivierung. Ein geschlossener Kanal liefert einen Fehler.
/// Der Aufruf wartet nicht auf die Ausführung oder den Erfolg des FD-Scans.
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

/// Gemeinsames absolutes Pin-Verzeichnis aller persistenten Prototypmaps.
pub const BPF_PIN_DIRECTORY: &str = "/sys/fs/bpf/tails-pdp";

/// Bildet den Pfad eines bekannten Mapnamens unter dem Pin-Verzeichnis.
///
/// Der Aufrufer verwendet vertrauenswürdige Mapnamen; der Helfer sanitisiert keine Pfade.
pub fn pinned_map_path(map_name: &str) -> PathBuf {
    Path::new(BPF_PIN_DIRECTORY).join(map_name)
}

/// Öffnet einen vorhandenen Pin als Aya-Array mit dem Werttyp `T`.
///
/// # Errors
///
/// Fehlender Zugriff, fehlender Pin oder nicht passender Array-/Werttyp liefert Fehler.
/// `T` muss die gemeinsamen ABI-Felder korrekt als `Pod` repräsentieren.
pub fn open_pinned_array<T: Pod>(map_name: &str) -> anyhow::Result<Array<MapData, T>> {
    let pin_path = pinned_map_path(map_name);
    let map_data = MapData::from_pin(&pin_path)
        .with_context(|| format!("failed to open pinned map '{}'", pin_path.display()))?;
    Array::try_from(Map::Array(map_data))
        .with_context(|| format!("failed to open {map_name} as array map"))
}

/// Öffnet einen vorhandenen Pin als Aya-HashMap mit Schlüssel `K` und Wert `V`.
///
/// # Errors
///
/// Pinzugriffsfehler und nicht passende Map-/Schlüssel-/Werttypen werden zurückgegeben.
/// `K` und `V` müssen die Maplayouts exakt repräsentieren.
pub fn open_pinned_hash_map<K: Pod, V: Pod>(
    map_name: &str,
) -> anyhow::Result<HashMap<MapData, K, V>> {
    let pin_path = pinned_map_path(map_name);
    let map_data = MapData::from_pin(&pin_path)
        .with_context(|| format!("failed to open pinned map '{}'", pin_path.display()))?;
    HashMap::try_from(Map::HashMap(map_data))
        .with_context(|| format!("failed to open {map_name} as hash map"))
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

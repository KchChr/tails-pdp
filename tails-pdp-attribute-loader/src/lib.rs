//! Pflegt Zeit und strukturierte Attribute für File-Open-Stream-Policies.
//!
//! Die Zeitmap enthält Unix-Sekunden. [`AttributeMaps`] kapselt die HashMap und aktive
//! Generation; neue Dateiinhalte werden vor dem Bankwechsel validiert. Der Namensraum
//! und die Objektidentität bestimmen System-, UID- und Ressourcenattribute.
//! Alle Mapoperationen setzen vorhandene Linux-BPF-Pins und passende Rechte voraus.
//! Fehler beim Erstladen verhindern den Runtime-Start; ungültige laufende Updates
//! werden protokolliert und lassen die aktive Generation unverändert.

mod stream_attributes;
mod time;

pub use stream_attributes::{
    AttributeMaps, default_stream_attributes_directory, open_attribute_maps, run_attribute_updater,
    write_current_attributes,
};
pub use time::{open_current_time_map, run_current_time_updater, write_current_time};

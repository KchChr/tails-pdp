//! Lesende CLI-Kommandos und auswählbare Map-/Quelldateipfade.
//!
//! Quelldateiverzeichnisse dienen der Namensauflösung für die Anzeige; die Runtime
//! wird hierdurch nicht umkonfiguriert. Schreibende Policy-Kommandos sind nicht vorhanden.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// Standardpin für statische Policies.
pub const DEFAULT_FILE_OPEN_STATIC_PIN_PATH: &str =
    "/sys/fs/bpf/tails-pdp/FILE_OPEN_STATIC_POLICIES";
/// Standardpin für Stream-Policies.
pub const DEFAULT_FILE_OPEN_STREAM_PIN_PATH: &str =
    "/sys/fs/bpf/tails-pdp/FILE_OPEN_STREAM_POLICIES";
/// Standardpin mit der aktiven Policygeneration.
pub const DEFAULT_POLICY_GENERATION_PIN_PATH: &str = "/sys/fs/bpf/tails-pdp/POLICY_GENERATION";
/// Standardpin mit der aktiven Attributgeneration.
pub const DEFAULT_ATTRIBUTE_GENERATION_PIN_PATH: &str =
    "/sys/fs/bpf/tails-pdp/ATTRIBUTE_GENERATION";
/// Standardpin für strukturierte Attribute.
pub const DEFAULT_ATTRIBUTES_PIN_PATH: &str = "/sys/fs/bpf/tails-pdp/ATTRIBUTES";
/// Standardverzeichnis zur ergänzenden Policy-Namensauflösung.
pub const DEFAULT_POLICY_DIRECTORY: &str = "policies";
/// Standardverzeichnis zur ergänzenden Attribut-Namensauflösung.
pub const DEFAULT_ATTRIBUTES_DIRECTORY: &str = "attributes";

#[derive(Parser, Debug)]
#[command(
    name = "tails-pdp-admintool",
    arg_required_else_help = true,
    about = "Liest die aktuell geladenen tails-pdp Policies und Attribute aus gepinnten eBPF-Maps."
)]
/// Lesende Mapauswahl, Quelldateizuordnung und Anzeigekommando.
pub struct Cli {
    #[arg(long, default_value = DEFAULT_FILE_OPEN_STATIC_PIN_PATH)]
    /// Pfad der lesend zu öffnenden statischen Policyarray.
    pub file_open_static_pin_path: PathBuf,

    #[arg(long, default_value = DEFAULT_FILE_OPEN_STREAM_PIN_PATH)]
    /// Pfad der lesend zu öffnenden Stream-Policyarray.
    pub file_open_stream_pin_path: PathBuf,

    #[arg(long, default_value = DEFAULT_POLICY_GENERATION_PIN_PATH)]
    /// Pfad der Policygeneration für die Auswahl der aktiven Bank.
    pub policy_generation_pin_path: PathBuf,

    #[arg(long, default_value = DEFAULT_ATTRIBUTE_GENERATION_PIN_PATH)]
    /// Pfad der Attributgeneration für die Auswahl der aktiven Bank.
    pub attribute_generation_pin_path: PathBuf,

    #[arg(long, default_value = DEFAULT_ATTRIBUTES_PIN_PATH)]
    /// Pfad der strukturierten Attribut-HashMap.
    pub attributes_pin_path: PathBuf,

    #[arg(long, default_value = DEFAULT_POLICY_DIRECTORY)]
    /// Policyquelldateien für Namensauflösung; kein Konfigurationsparameter der Runtime.
    pub policy_dir: PathBuf,

    #[arg(long, default_value = DEFAULT_ATTRIBUTES_DIRECTORY)]
    /// Attributquelldateien für Namensauflösung; verändert die Runtime nicht.
    pub attributes_dir: PathBuf,

    #[command(subcommand)]
    /// Ausgewählte lesende Darstellung.
    pub command: Command,
}

#[derive(Subcommand, Debug)]
/// Unterstützte lesende CLI-Kommandos.
pub enum Command {
    /// Zeigt den allgemeinen geladenen Mapbestand.
    Show,
    /// Zeigt den aktiven Zustand.
    ShowActive,
    /// Zeigt die ausgewählten Policies.
    ShowPolicies,
    /// Zeigt die ausgewählten Attribute.
    ShowAttributes,
}

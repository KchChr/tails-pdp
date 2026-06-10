use std::path::PathBuf;

use clap::{Parser, Subcommand};

pub const DEFAULT_FILE_OPEN_STATIC_PIN_PATH: &str =
    "/sys/fs/bpf/tails-pdp/FILE_OPEN_STATIC_POLICIES";
pub const DEFAULT_FILE_OPEN_STREAM_PIN_PATH: &str =
    "/sys/fs/bpf/tails-pdp/FILE_OPEN_STREAM_POLICIES";
pub const DEFAULT_POLICY_GENERATION_PIN_PATH: &str = "/sys/fs/bpf/tails-pdp/POLICY_GENERATION";
pub const DEFAULT_ATTRIBUTE_GENERATION_PIN_PATH: &str =
    "/sys/fs/bpf/tails-pdp/ATTRIBUTE_GENERATION";
pub const DEFAULT_ATTRIBUTES_PIN_PATH: &str = "/sys/fs/bpf/tails-pdp/ATTRIBUTES";
pub const DEFAULT_POLICY_DIRECTORY: &str = "policies";
pub const DEFAULT_ENVIRONMENT_DIRECTORY: &str = "environment";

#[derive(Parser, Debug)]
#[command(
    name = "tails-pdp-admintool",
    arg_required_else_help = true,
    about = "Liest die aktuell geladenen tails-pdp Policies und Attribute aus gepinnten eBPF-Maps."
)]
pub struct Cli {
    #[arg(long, default_value = DEFAULT_FILE_OPEN_STATIC_PIN_PATH)]
    pub file_open_static_pin_path: PathBuf,

    #[arg(long, default_value = DEFAULT_FILE_OPEN_STREAM_PIN_PATH)]
    pub file_open_stream_pin_path: PathBuf,

    #[arg(long, default_value = DEFAULT_POLICY_GENERATION_PIN_PATH)]
    pub policy_generation_pin_path: PathBuf,

    #[arg(long, default_value = DEFAULT_ATTRIBUTE_GENERATION_PIN_PATH)]
    pub attribute_generation_pin_path: PathBuf,

    #[arg(long, default_value = DEFAULT_ATTRIBUTES_PIN_PATH)]
    pub attributes_pin_path: PathBuf,

    #[arg(long, default_value = DEFAULT_POLICY_DIRECTORY)]
    pub policy_dir: PathBuf,

    #[arg(long, default_value = DEFAULT_ENVIRONMENT_DIRECTORY)]
    pub environment_dir: PathBuf,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    Show,
    ShowActive,
    ShowPolicies,
    ShowAttributes,
}

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};
use tails_pdp_common::{ANY_SUBJECT, Entitlement, PolicyAction, StreamAttribute, StreamOperator};

pub const DEFAULT_STATIC_PIN_PATH: &str = "/sys/fs/bpf/tails-pdp/STATIC_POLICY";
pub const DEFAULT_STREAM_PIN_PATH: &str = "/sys/fs/bpf/tails-pdp/STREAM_POLICY";

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum EntitlementArg {
    Permit,
    Deny,
}

impl From<EntitlementArg> for Entitlement {
    fn from(value: EntitlementArg) -> Self {
        match value {
            EntitlementArg::Permit => Entitlement::Permit,
            EntitlementArg::Deny => Entitlement::Deny,
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum ActionArg {
    FileOpen,
    TaskSetNice,
}

impl From<ActionArg> for PolicyAction {
    fn from(value: ActionArg) -> Self {
        match value {
            ActionArg::FileOpen => PolicyAction::FileOpen,
            ActionArg::TaskSetNice => PolicyAction::TaskSetNice,
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum StreamAttributeArg {
    Time,
}

impl From<StreamAttributeArg> for StreamAttribute {
    fn from(value: StreamAttributeArg) -> Self {
        match value {
            StreamAttributeArg::Time => StreamAttribute::Time,
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum StreamOperatorArg {
    LessThan,
    LessThanOrEqual,
    Equal,
    GreaterThanOrEqual,
    GreaterThan,
}

impl From<StreamOperatorArg> for StreamOperator {
    fn from(value: StreamOperatorArg) -> Self {
        match value {
            StreamOperatorArg::LessThan => StreamOperator::LessThan,
            StreamOperatorArg::LessThanOrEqual => StreamOperator::LessThanOrEqual,
            StreamOperatorArg::Equal => StreamOperator::Equal,
            StreamOperatorArg::GreaterThanOrEqual => StreamOperator::GreaterThanOrEqual,
            StreamOperatorArg::GreaterThan => StreamOperator::GreaterThan,
        }
    }
}

#[derive(Parser, Debug)]
#[command(
    name = "tails-pdp-admintool",
    arg_required_else_help = true,
    about = "Verwaltet die gepinnten STATIC_POLICY- und STREAM_POLICY-eBPF-Maps."
)]
pub struct Cli {
    #[arg(long, default_value = DEFAULT_STATIC_PIN_PATH)]
    pub static_pin_path: PathBuf,

    #[arg(long, default_value = DEFAULT_STREAM_PIN_PATH)]
    pub stream_pin_path: PathBuf,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Zeigt alle STATIC_POLICY- und STREAM_POLICY-Eintraege an.
    Show,
    /// Zeigt nur aktive STATIC_POLICY- und STREAM_POLICY-Eintraege an.
    ShowActive,
    /// Setzt einen STATIC_POLICY-Slot auf disabled zurueck.
    Clear { index: u32 },
    /// Setzt einen STREAM_POLICY-Slot auf disabled zurueck.
    ClearStream { index: u32 },
    /// Schreibt einen STATIC_POLICY-Eintrag an einen Index.
    Set {
        index: u32,
        #[arg(long, value_enum)]
        entitlement: EntitlementArg,
        #[arg(long, value_enum)]
        action: ActionArg,
        #[arg(long, default_value_t = ANY_SUBJECT)]
        subject: u32,
        #[arg(long, default_value = "")]
        command: String,
        #[arg(long, default_value = "")]
        resource: String,
    },
    /// Schreibt einen STREAM_POLICY-Eintrag an einen Index.
    SetStream {
        index: u32,
        #[arg(long, value_enum)]
        entitlement: EntitlementArg,
        #[arg(long, value_enum)]
        action: ActionArg,
        #[arg(long, default_value_t = ANY_SUBJECT)]
        subject: u32,
        #[arg(long, value_enum, default_value_t = StreamAttributeArg::Time)]
        attribute: StreamAttributeArg,
        #[arg(long, value_enum)]
        operator: StreamOperatorArg,
        #[arg(long)]
        modulo: u64,
        #[arg(long)]
        value: u64,
    },
    /// Laedt die im Tool hinterlegten Beispielpolicies.
    LoadExamples,
    /// Laedt Beispiel-Stream-Policies.
    LoadStreamExamples,
}

impl Command {
    pub fn requires_root(&self) -> bool {
        matches!(
            self,
            Self::Clear { .. }
                | Self::ClearStream { .. }
                | Self::Set { .. }
                | Self::SetStream { .. }
                | Self::LoadExamples
                | Self::LoadStreamExamples
        )
    }
}

pub fn print_usage() {
    println!("tails-pdp-admintool");
    println!();
    println!("Verwaltet die gepinnten STATIC_POLICY- und STREAM_POLICY-eBPF-Maps.");
    println!();
    println!("USAGE:");
    println!(
        "  tails-pdp-admintool [--static-pin-path <PATH>] [--stream-pin-path <PATH>] <COMMAND>"
    );
    println!();
    println!("COMMANDS:");
    println!("  show");
    println!("      Zeigt alle STATIC_POLICY- und STREAM_POLICY-Eintraege an.");
    println!("      Kein sudo erforderlich.");
    println!();
    println!("  show-active");
    println!("      Zeigt nur aktive STATIC_POLICY- und STREAM_POLICY-Eintraege an.");
    println!("      Kein sudo erforderlich.");
    println!();
    println!("  clear <INDEX>");
    println!("      Setzt einen Slot auf disabled zurueck.");
    println!("      sudo erforderlich.");
    println!();
    println!("  clear-stream <INDEX>");
    println!("      Setzt einen STREAM_POLICY-Slot auf disabled zurueck.");
    println!("      sudo erforderlich.");
    println!();
    println!("  set <INDEX> --entitlement <permit|deny> --action <file-open|task-set-nice>");
    println!("      [--subject <UID>] [--command <NAME>] [--resource <PFAD>]");
    println!("      Schreibt einen STATIC_POLICY-Eintrag.");
    println!("      sudo erforderlich.");
    println!();
    println!("  set-stream <INDEX> --entitlement <permit|deny> --action <file-open|task-set-nice>");
    println!(
        "      [--subject <UID>] [--attribute <time>] --operator <...> --modulo <N> --value <N>"
    );
    println!("      Schreibt einen STREAM_POLICY-Eintrag.");
    println!("      sudo erforderlich.");
    println!();
    println!("  load-examples");
    println!("      Laedt die hinterlegten Beispielpolicies.");
    println!("      sudo erforderlich.");
    println!();
    println!("  load-stream-examples");
    println!("      Laedt hinterlegte Beispiel-Stream-Policies.");
    println!("      sudo erforderlich.");
    println!();
    println!("OPTIONS:");
    println!("  --static-pin-path <PATH>");
    println!("      Standard: {}", DEFAULT_STATIC_PIN_PATH);
    println!("  --stream-pin-path <PATH>");
    println!("      Standard: {}", DEFAULT_STREAM_PIN_PATH);
    println!("  -h, --help");
    println!("      Zeigt diese Hilfe an.");
    println!();
    println!("BEISPIELE:");
    println!("  tails-pdp-admintool show");
    println!("  tails-pdp-admintool show-active");
    println!("  sudo tails-pdp-admintool clear 0");
    println!("  sudo tails-pdp-admintool clear-stream 0");
    println!(
        "  sudo tails-pdp-admintool set 0 --entitlement deny --action file-open --subject 0 --command cat --resource /etc/shadow"
    );
    println!(
        "  sudo tails-pdp-admintool set-stream 0 --entitlement permit --action file-open --subject 1000 --attribute time --operator less-than --modulo 10 --value 5"
    );
    println!("  sudo tails-pdp-admintool load-examples");
    println!("  sudo tails-pdp-admintool load-stream-examples");
}

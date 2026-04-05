use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};
use tails_pdp_common::{
    ANY_SUBJECT, Entitlement, SocketFamily, SocketTransport, StreamAttribute, StreamOperator,
};

pub const DEFAULT_FILE_OPEN_STATIC_PIN_PATH: &str =
    "/sys/fs/bpf/tails-pdp/FILE_OPEN_STATIC_POLICIES";
pub const DEFAULT_FILE_OPEN_STREAM_PIN_PATH: &str =
    "/sys/fs/bpf/tails-pdp/FILE_OPEN_STREAM_POLICIES";
pub const DEFAULT_SOCKET_BIND_STATIC_PIN_PATH: &str =
    "/sys/fs/bpf/tails-pdp/SOCKET_BIND_STATIC_POLICIES";
pub const DEFAULT_SOCKET_BIND_STREAM_PIN_PATH: &str =
    "/sys/fs/bpf/tails-pdp/SOCKET_BIND_STREAM_POLICIES";

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
    SocketBind,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum SocketFamilyArg {
    Any,
    Inet,
    Inet6,
}

impl From<SocketFamilyArg> for SocketFamily {
    fn from(value: SocketFamilyArg) -> Self {
        match value {
            SocketFamilyArg::Any => SocketFamily::Any,
            SocketFamilyArg::Inet => SocketFamily::Inet,
            SocketFamilyArg::Inet6 => SocketFamily::Inet6,
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum SocketTransportArg {
    Any,
    Tcp,
    Udp,
}

impl From<SocketTransportArg> for SocketTransport {
    fn from(value: SocketTransportArg) -> Self {
        match value {
            SocketTransportArg::Any => SocketTransport::Any,
            SocketTransportArg::Tcp => SocketTransport::Tcp,
            SocketTransportArg::Udp => SocketTransport::Udp,
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
    about = "Verwaltet die hook-spezifischen eBPF-Policy-Maps."
)]
pub struct Cli {
    #[arg(long, default_value = DEFAULT_FILE_OPEN_STATIC_PIN_PATH)]
    pub file_open_static_pin_path: PathBuf,

    #[arg(long, default_value = DEFAULT_FILE_OPEN_STREAM_PIN_PATH)]
    pub file_open_stream_pin_path: PathBuf,

    #[arg(long, default_value = DEFAULT_SOCKET_BIND_STATIC_PIN_PATH)]
    pub socket_bind_static_pin_path: PathBuf,

    #[arg(long, default_value = DEFAULT_SOCKET_BIND_STREAM_PIN_PATH)]
    pub socket_bind_stream_pin_path: PathBuf,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    Show,
    ShowActive,
    ClearAll {
        #[arg(long, value_enum)]
        action: Option<ActionArg>,
    },
    Clear {
        index: u32,
        #[arg(long, value_enum)]
        action: ActionArg,
    },
    ClearStream {
        index: u32,
        #[arg(long, value_enum)]
        action: ActionArg,
    },
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
        #[arg(long, value_enum, default_value_t = SocketFamilyArg::Any)]
        family: SocketFamilyArg,
        #[arg(long, value_enum, default_value_t = SocketTransportArg::Any)]
        transport: SocketTransportArg,
        #[arg(long, default_value_t = 0)]
        port: u16,
    },
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
        #[arg(long, default_value = "")]
        resource: String,
        #[arg(long, value_enum, default_value_t = SocketFamilyArg::Any)]
        family: SocketFamilyArg,
        #[arg(long, value_enum, default_value_t = SocketTransportArg::Any)]
        transport: SocketTransportArg,
        #[arg(long, default_value_t = 0)]
        port: u16,
        #[arg(long, value_enum)]
        operator: StreamOperatorArg,
        #[arg(long)]
        modulo: u64,
        #[arg(long)]
        value: u64,
    },
    LoadExamples,
    LoadStreamExamples,
}

impl Command {
    pub fn requires_root(&self) -> bool {
        matches!(
            self,
            Self::ClearAll { .. }
                | Self::Clear { .. }
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
    println!("Verwaltet die hook-spezifischen eBPF-Policy-Maps.");
    println!();
    println!("USAGE:");
    println!("  tails-pdp-admintool <COMMAND> [OPTIONS]");
    println!();
    println!("COMMANDS:");
    println!("  show");
    println!("      Zeigt alle hook-spezifischen Static- und Stream-Policies an.");
    println!("  show-active");
    println!("      Zeigt nur aktive hook-spezifische Policies an.");
    println!("  clear-all [--action <file-open|socket-bind>]");
    println!("      Ohne --action: leert alle Static- und Stream-Policies aller Hooks.");
    println!("      Mit --action: leert alle Static- und Stream-Policies des Hooks.");
    println!("  clear <INDEX> --action <file-open|socket-bind>");
    println!("      Setzt einen Static-Policy-Slot des Hooks auf disabled zurueck.");
    println!("  clear-stream <INDEX> --action <file-open|socket-bind>");
    println!("      Setzt einen Stream-Policy-Slot des Hooks auf disabled zurueck.");
    println!("  set <INDEX> --entitlement <permit|deny> --action <file-open|socket-bind>");
    println!("      file-open: [--subject <UID>] [--command <NAME>] [--resource <PFAD>]");
    println!(
        "      socket-bind: [--subject <UID>] [--family <any|inet|inet6>] [--transport <any|tcp|udp>] [--resource <IP>] [--port <N>]"
    );
    println!("  set-stream <INDEX> --entitlement <permit|deny> --action <file-open|socket-bind>");
    println!(
        "      [--subject <UID>] [--attribute <time>] --operator <...> --modulo <N> --value <N>"
    );
    println!("      file-open: [--resource <PFAD>]");
    println!(
        "      socket-bind: [--family <any|inet|inet6>] [--transport <any|tcp|udp>] [--resource <IP>] [--port <N>]"
    );
    println!("  load-examples");
    println!("  load-stream-examples");
    println!();
    println!("BEISPIELE:");
    println!("  tails-pdp-admintool show");
    println!("  tails-pdp-admintool show-active");
    println!("  sudo tails-pdp-admintool clear-all");
    println!("  sudo tails-pdp-admintool clear-all --action file-open");
    println!(
        "  sudo tails-pdp-admintool set 0 --entitlement deny --action file-open --subject 1000 --command cat --resource /home/hntr/test.txt"
    );
    println!(
        "  sudo tails-pdp-admintool set 0 --entitlement deny --action socket-bind --subject 1000 --family inet --transport tcp --resource 0.0.0.0 --port 8080"
    );
    println!(
        "  sudo tails-pdp-admintool set-stream 0 --entitlement permit --action socket-bind --subject 1000 --attribute time --family inet --transport tcp --resource 0.0.0.0 --port 8080 --operator less-than --modulo 10 --value 5"
    );
}

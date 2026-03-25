use std::{env, path::PathBuf};

use anyhow::{Context, anyhow, bail};
use aya::maps::{Array, Map, MapData};
use clap::{Parser, Subcommand, ValueEnum, error::ErrorKind};
use tails_pdp_common::{
    ANY_SUBJECT, COMMAND_LEN, Entitlement, PolicyAction, RESOURCE_LEN, StaticPolicy, StreamPolicy,
};

const DEFAULT_STATIC_PIN_PATH: &str = "/sys/fs/bpf/tails-pdp/STATIC_POLICY";
const DEFAULT_STREAM_PIN_PATH: &str = "/sys/fs/bpf/tails-pdp/STREAM_POLICY";

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
enum EntitlementArg {
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
enum ActionArg {
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

#[derive(Parser, Debug)]
#[command(
    name = "tails-pdp-admintool",
    arg_required_else_help = true,
    about = "Verwaltet die gepinnte STATIC_POLICY-eBPF-Map.",
    after_help = "Beispiele:\n  tp-admin show\n  tp-admin clear 0\n  tp-admin set 0 --entitlement deny --action file-open --subject 0 --command cat --resource shadow\n  tp-admin load-examples"
)]
struct Cli {
    #[arg(long, default_value = DEFAULT_STATIC_PIN_PATH)]
    static_pin_path: PathBuf,

    #[arg(long, default_value = DEFAULT_STREAM_PIN_PATH)]
    stream_pin_path: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Zeigt alle STATIC_POLICY-Eintraege an.
    Show,
    /// Zeigt nur aktive STATIC_POLICY-Eintraege an.
    ShowActive,
    /// Setzt einen Policy-Slot auf disabled zurueck.
    Clear { index: u32 },
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
    /// Laedt die im Tool hinterlegten Beispielpolicies.
    LoadExamples,
}

impl Command {
    fn requires_root(&self) -> bool {
        matches!(
            self,
            Self::Clear { .. } | Self::Set { .. } | Self::LoadExamples
        )
    }
}

fn open_static_policy(path: &PathBuf) -> anyhow::Result<Array<MapData, StaticPolicy>> {
    let map_data = MapData::from_pin(path)
        .with_context(|| format!("failed to open pinned map at {}", path.display()))?;
    let map = Map::Array(map_data);
    Array::try_from(map).context("failed to treat pinned map as Array<StaticPolicy>")
}

fn open_stream_policy(path: &PathBuf) -> anyhow::Result<Array<MapData, StreamPolicy>> {
    let map_data = MapData::from_pin(path)
        .with_context(|| format!("failed to open pinned map at {}", path.display()))?;
    let map = Map::Array(map_data);
    Array::try_from(map).context("failed to treat pinned map as Array<StreamPolicy>")
}

fn fixed_string(bytes: &[u8]) -> String {
    let len = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..len]).into_owned()
}

fn validate_len(name: &str, value: &str, max_len: usize) -> anyhow::Result<()> {
    if value.len() > max_len {
        bail!("{name} too long: {} > {}", value.len(), max_len);
    }
    Ok(())
}

fn show_static(map: &Array<MapData, StaticPolicy>, active_only: bool) -> anyhow::Result<()> {
    println!("STATIC_POLICY:");
    for index in 0..map.len() {
        let policy = map
            .get(&index, 0)
            .with_context(|| format!("failed to read STATIC_POLICY[{index}]"))?;
        if active_only && policy.enabled == 0 {
            continue;
        }
        let command = fixed_string(&policy.command);
        let resource = fixed_string(&policy.resource);
        println!(
            "[{index}] enabled={} entitlement={:?} action={:?} subject={} command={:?} resource={:?}",
            policy.enabled, policy.entitlement, policy.action, policy.subject, command, resource,
        );
    }
    println!();
    Ok(())
}

fn show_stream(map: &Array<MapData, StreamPolicy>, active_only: bool) -> anyhow::Result<()> {
    println!("STREAM_POLICY:");
    for index in 0..map.len() {
        let policy = map
            .get(&index, 0)
            .with_context(|| format!("failed to read STREAM_POLICY[{index}]"))?;
        if active_only && policy.enabled == 0 {
            continue;
        }
        println!(
            "[{index}] enabled={} entitlement={:?} action={:?} attribute={:?} operator={:?} modulo={} value={}",
            policy.enabled,
            policy.entitlement,
            policy.action,
            policy.attribute,
            policy.operator,
            policy.modulo,
            policy.value,
        );
    }
    Ok(())
}

fn load_examples(map: &mut Array<MapData, StaticPolicy>) -> anyhow::Result<()> {
    let example_policies = [
        StaticPolicy::new(
            Entitlement::Deny,
            ANY_SUBJECT,
            PolicyAction::FileOpen,
            "cat",
            "shadow",
        ),
        StaticPolicy::new(Entitlement::Deny, 0, PolicyAction::TaskSetNice, "", ""),
    ];

    for index in 0..map.len() {
        map.set(index, StaticPolicy::disabled(), 0)
            .with_context(|| format!("failed to clear STATIC_POLICY[{index}]"))?;
    }

    for (index, policy) in example_policies.into_iter().enumerate() {
        map.set(index as u32, policy, 0)
            .with_context(|| format!("failed to write STATIC_POLICY[{index}]"))?;
    }

    Ok(())
}

fn set_policy(
    map: &mut Array<MapData, StaticPolicy>,
    index: u32,
    entitlement: EntitlementArg,
    action: ActionArg,
    subject: u32,
    command: String,
    resource: String,
) -> anyhow::Result<()> {
    validate_len("command", &command, COMMAND_LEN)?;
    validate_len("resource", &resource, RESOURCE_LEN)?;

    let policy = StaticPolicy::new(
        entitlement.into(),
        subject,
        action.into(),
        &command,
        &resource,
    );

    map.set(index, policy, 0)
        .with_context(|| format!("failed to write STATIC_POLICY[{index}]"))?;

    Ok(())
}

fn clear_policy(map: &mut Array<MapData, StaticPolicy>, index: u32) -> anyhow::Result<()> {
    map.set(index, StaticPolicy::disabled(), 0)
        .with_context(|| format!("failed to clear STATIC_POLICY[{index}]"))?;
    Ok(())
}

fn print_usage() -> anyhow::Result<()> {
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
    println!("  set <INDEX> --entitlement <permit|deny> --action <file-open|task-set-nice>");
    println!("      [--subject <UID>] [--command <NAME>] [--resource <NAME>]");
    println!("      Schreibt einen STATIC_POLICY-Eintrag.");
    println!("      sudo erforderlich.");
    println!();
    println!("  load-examples");
    println!("      Laedt die hinterlegten Beispielpolicies.");
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
    println!(
        "  sudo tails-pdp-admintool set 0 --entitlement deny --action file-open --subject 0 --command cat --resource shadow"
    );
    println!("  sudo tails-pdp-admintool load-examples");
    Ok(())
}

fn ensure_privileges(command: &Command) -> anyhow::Result<()> {
    if command.requires_root() && unsafe { libc::geteuid() } != 0 {
        bail!("this command modifies pinned eBPF maps and must be run with sudo");
    }
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let args: Vec<_> = env::args_os().collect();
    if args.len() == 1
        || matches!(
            args.get(1).and_then(|arg| arg.to_str()),
            Some("-h" | "--help")
        )
    {
        print_usage()?;
        return Ok(());
    }

    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => match error.kind() {
            ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => error.exit(),
            _ => {
                error.print()?;
                println!();
                print_usage()?;
                std::process::exit(2);
            }
        },
    };
    ensure_privileges(&cli.command)?;
    let mut static_map = open_static_policy(&cli.static_pin_path)?;

    match cli.command {
        Command::Show => {
            let stream_map = open_stream_policy(&cli.stream_pin_path)?;
            show_static(&static_map, false)?;
            show_stream(&stream_map, false)
        }
        Command::ShowActive => {
            let stream_map = open_stream_policy(&cli.stream_pin_path)?;
            show_static(&static_map, true)?;
            show_stream(&stream_map, true)
        }
        Command::Clear { index } => clear_policy(&mut static_map, index),
        Command::Set {
            index,
            entitlement,
            action,
            subject,
            command,
            resource,
        } => set_policy(
            &mut static_map,
            index,
            entitlement,
            action,
            subject,
            command,
            resource,
        ),
        Command::LoadExamples => load_examples(&mut static_map),
    }
    .map_err(|error| anyhow!(error))
}

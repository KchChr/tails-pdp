mod cli;
mod maps;
mod output;

use std::env;

use anyhow::{anyhow, bail};
use clap::{Parser, error::ErrorKind};
use tails_pdp_common::{ANY_SUBJECT, COMMAND_LEN, Entitlement, RESOURCE_LEN, StaticPolicy};

use crate::{
    cli::{Cli, Command, print_usage},
    maps::{open_static_policy, open_stream_policy},
    output::{show_static, show_stream},
};

fn validate_len(name: &str, value: &str, max_len: usize) -> anyhow::Result<()> {
    if value.len() > max_len {
        bail!("{name} too long: {} > {}", value.len(), max_len);
    }
    Ok(())
}

fn clear_static_policy(map: &mut maps::StaticPolicyMap, index: u32) -> anyhow::Result<()> {
    map.set(index, StaticPolicy::disabled(), 0)
        .map_err(anyhow::Error::from)
        .map_err(|error| anyhow!("failed to clear STATIC_POLICY[{index}]: {error}"))
}

fn set_static_policy(
    map: &mut maps::StaticPolicyMap,
    index: u32,
    entitlement: cli::EntitlementArg,
    action: cli::ActionArg,
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
    )
    .resolve_resource_identity()
    .map_err(anyhow::Error::from)
    .map_err(|error| anyhow!("failed to resolve STATIC_POLICY[{index}] resource: {error}"))?;

    map.set(index, policy, 0)
        .map_err(anyhow::Error::from)
        .map_err(|error| anyhow!("failed to write STATIC_POLICY[{index}]: {error}"))
}

fn load_example_static_policies(map: &mut maps::StaticPolicyMap) -> anyhow::Result<()> {
    let example_policies = [
        StaticPolicy::new(
            Entitlement::Deny,
            ANY_SUBJECT,
            tails_pdp_common::PolicyAction::FileOpen,
            "cat",
            "/etc/shadow",
        ),
        StaticPolicy::new(
            Entitlement::Deny,
            0,
            tails_pdp_common::PolicyAction::TaskSetNice,
            "",
            "",
        ),
    ];

    for index in 0..map.len() {
        map.set(index, StaticPolicy::disabled(), 0)
            .map_err(anyhow::Error::from)
            .map_err(|error| anyhow!("failed to clear STATIC_POLICY[{index}]: {error}"))?;
    }

    for (index, policy) in example_policies.into_iter().enumerate() {
        let policy = policy
            .resolve_resource_identity()
            .map_err(anyhow::Error::from)
            .map_err(|error| {
                anyhow!("failed to resolve example STATIC_POLICY[{index}] resource: {error}")
            })?;
        map.set(index as u32, policy, 0)
            .map_err(anyhow::Error::from)
            .map_err(|error| anyhow!("failed to write STATIC_POLICY[{index}]: {error}"))?;
    }

    Ok(())
}

fn ensure_privileges(command: &Command) -> anyhow::Result<()> {
    if command.requires_root() && unsafe { libc::geteuid() } != 0 {
        bail!("this command modifies pinned eBPF maps and must be run with sudo");
    }
    Ok(())
}

pub fn run() -> anyhow::Result<()> {
    let args: Vec<_> = env::args_os().collect();
    if args.len() == 1
        || matches!(
            args.get(1).and_then(|arg| arg.to_str()),
            Some("-h" | "--help")
        )
    {
        print_usage();
        return Ok(());
    }

    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => match error.kind() {
            ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => error.exit(),
            _ => {
                error.print()?;
                println!();
                print_usage();
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
        Command::Clear { index } => clear_static_policy(&mut static_map, index),
        Command::Set {
            index,
            entitlement,
            action,
            subject,
            command,
            resource,
        } => set_static_policy(
            &mut static_map,
            index,
            entitlement,
            action,
            subject,
            command,
            resource,
        ),
        Command::LoadExamples => load_example_static_policies(&mut static_map),
    }
}

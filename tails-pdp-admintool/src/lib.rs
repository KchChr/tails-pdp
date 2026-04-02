mod cli;
mod maps;
mod output;

use std::env;

use anyhow::{anyhow, bail};
use clap::{Parser, error::ErrorKind};
use tails_pdp_common::{
    ANY_SUBJECT, COMMAND_LEN, Entitlement, PolicyAction, RESOURCE_LEN,
    STATIC_POLICY_SLOTS_PER_HOOK, STREAM_POLICY_SLOTS_PER_HOOK, StaticPolicy, StreamPolicy,
};

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

fn hook_local_slot(
    action: PolicyAction,
    local_index: u32,
    slots_per_hook: u32,
) -> anyhow::Result<u32> {
    if local_index >= slots_per_hook {
        bail!(
            "local hook index {} out of range for {:?}; max is {}",
            local_index,
            action,
            slots_per_hook - 1
        );
    }
    Ok(action.local_slot(local_index, slots_per_hook))
}

fn clear_static_policy(
    map: &mut maps::StaticPolicyMap,
    action: cli::ActionArg,
    index: u32,
) -> anyhow::Result<()> {
    let slot = hook_local_slot(action.into(), index, STATIC_POLICY_SLOTS_PER_HOOK)?;
    map.set(slot, StaticPolicy::disabled(), 0)
        .map_err(anyhow::Error::from)
        .map_err(|error| {
            anyhow!(
                "failed to clear STATIC_POLICY[{slot}] from {:?}[{index}]: {error}",
                action
            )
        })
}

fn clear_stream_policy(
    map: &mut maps::StreamPolicyMap,
    action: cli::ActionArg,
    index: u32,
) -> anyhow::Result<()> {
    let slot = hook_local_slot(action.into(), index, STREAM_POLICY_SLOTS_PER_HOOK)?;
    map.set(slot, StreamPolicy::disabled(), 0)
        .map_err(anyhow::Error::from)
        .map_err(|error| {
            anyhow!(
                "failed to clear STREAM_POLICY[{slot}] from {:?}[{index}]: {error}",
                action
            )
        })
}

fn set_static_policy(
    map: &mut maps::StaticPolicyMap,
    index: u32,
    entitlement: cli::EntitlementArg,
    action: cli::ActionArg,
    subject: u32,
    command: String,
    resource: String,
    family: cli::SocketFamilyArg,
    transport: cli::SocketTransportArg,
    port: u16,
) -> anyhow::Result<()> {
    validate_len("command", &command, COMMAND_LEN)?;
    validate_len("resource", &resource, RESOURCE_LEN)?;
    let policy_action: PolicyAction = action.into();
    let slot = hook_local_slot(policy_action, index, STATIC_POLICY_SLOTS_PER_HOOK)?;

    let mut policy = StaticPolicy::new(
        entitlement.into(),
        subject,
        policy_action,
        &command,
        &resource,
    );
    policy.socket_family = family.into();
    policy.socket_transport = transport.into();
    policy.socket_port = port;
    let policy = policy
        .resolve_resource_identity()
        .map_err(anyhow::Error::from)
        .map_err(|error| anyhow!("failed to resolve STATIC_POLICY[{index}] resource: {error}"))?;

    map.set(slot, policy, 0)
        .map_err(anyhow::Error::from)
        .map_err(|error| {
            anyhow!(
                "failed to write STATIC_POLICY[{slot}] from {:?}[{index}]: {error}",
                action
            )
        })
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

    let mut next_index = [0u32; tails_pdp_common::POLICY_HOOK_COUNT as usize];
    for policy in example_policies.into_iter() {
        let hook_slot = policy.action.hook_slot() as usize;
        let index = next_index[hook_slot];
        let slot = hook_local_slot(policy.action, index, STATIC_POLICY_SLOTS_PER_HOOK)?;
        let policy = policy
            .resolve_resource_identity()
            .map_err(anyhow::Error::from)
            .map_err(|error| {
                anyhow!("failed to resolve example STATIC_POLICY[{index}] resource: {error}")
            })?;
        map.set(slot, policy, 0)
            .map_err(anyhow::Error::from)
            .map_err(|error| anyhow!("failed to write STATIC_POLICY[{slot}]: {error}"))?;
        next_index[hook_slot] += 1;
    }

    Ok(())
}

fn set_stream_policy(
    map: &mut maps::StreamPolicyMap,
    index: u32,
    entitlement: cli::EntitlementArg,
    action: cli::ActionArg,
    subject: u32,
    attribute: cli::StreamAttributeArg,
    resource: String,
    family: cli::SocketFamilyArg,
    transport: cli::SocketTransportArg,
    port: u16,
    operator: cli::StreamOperatorArg,
    modulo: u64,
    value: u64,
) -> anyhow::Result<()> {
    validate_len("resource", &resource, RESOURCE_LEN)?;
    let policy_action: PolicyAction = action.into();
    let slot = hook_local_slot(policy_action, index, STREAM_POLICY_SLOTS_PER_HOOK)?;

    let mut policy = StreamPolicy::time(
        entitlement.into(),
        subject,
        policy_action,
        &resource,
        operator.into(),
        modulo,
        value,
    );
    policy.attribute = attribute.into();
    policy.socket_family = family.into();
    policy.socket_transport = transport.into();
    policy.socket_port = port;
    policy = policy
        .resolve_resource_identity()
        .map_err(anyhow::Error::from)
        .map_err(|error| anyhow!("failed to resolve STREAM_POLICY[{index}] resource: {error}"))?;

    map.set(slot, policy, 0)
        .map_err(anyhow::Error::from)
        .map_err(|error| {
            anyhow!(
                "failed to write STREAM_POLICY[{slot}] from {:?}[{index}]: {error}",
                action
            )
        })
}

fn load_example_stream_policies(map: &mut maps::StreamPolicyMap) -> anyhow::Result<()> {
    let example_policies = [StreamPolicy::time(
        Entitlement::Permit,
        1000,
        tails_pdp_common::PolicyAction::FileOpen,
        "/home/hntr/test.txt",
        tails_pdp_common::StreamOperator::LessThan,
        10,
        5,
    )];

    for index in 0..map.len() {
        map.set(index, StreamPolicy::disabled(), 0)
            .map_err(anyhow::Error::from)
            .map_err(|error| anyhow!("failed to clear STREAM_POLICY[{index}]: {error}"))?;
    }

    let mut next_index = [0u32; tails_pdp_common::POLICY_HOOK_COUNT as usize];
    for policy in example_policies.into_iter() {
        let hook_slot = policy.action.hook_slot() as usize;
        let index = next_index[hook_slot];
        let slot = hook_local_slot(policy.action, index, STREAM_POLICY_SLOTS_PER_HOOK)?;
        let policy = policy
            .resolve_resource_identity()
            .map_err(anyhow::Error::from)
            .map_err(|error| {
                anyhow!("failed to resolve example STREAM_POLICY[{index}] resource: {error}")
            })?;
        map.set(slot, policy, 0)
            .map_err(anyhow::Error::from)
            .map_err(|error| anyhow!("failed to write STREAM_POLICY[{slot}]: {error}"))?;
        next_index[hook_slot] += 1;
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

    match cli.command {
        Command::Show => {
            let static_map = open_static_policy(&cli.static_pin_path)?;
            let stream_map = open_stream_policy(&cli.stream_pin_path)?;
            show_static(&static_map, false)?;
            show_stream(&stream_map, false)
        }
        Command::ShowActive => {
            let static_map = open_static_policy(&cli.static_pin_path)?;
            let stream_map = open_stream_policy(&cli.stream_pin_path)?;
            show_static(&static_map, true)?;
            show_stream(&stream_map, true)
        }
        Command::Clear { index, action } => {
            let mut static_map = open_static_policy(&cli.static_pin_path)?;
            clear_static_policy(&mut static_map, action, index)
        }
        Command::ClearStream { index, action } => {
            let mut stream_map = open_stream_policy(&cli.stream_pin_path)?;
            clear_stream_policy(&mut stream_map, action, index)
        }
        Command::Set {
            index,
            entitlement,
            action,
            subject,
            command,
            resource,
            family,
            transport,
            port,
        } => {
            let mut static_map = open_static_policy(&cli.static_pin_path)?;
            set_static_policy(
                &mut static_map,
                index,
                entitlement,
                action,
                subject,
                command,
                resource,
                family,
                transport,
                port,
            )
        }
        Command::SetStream {
            index,
            entitlement,
            action,
            subject,
            attribute,
            resource,
            family,
            transport,
            port,
            operator,
            modulo,
            value,
        } => {
            let mut stream_map = open_stream_policy(&cli.stream_pin_path)?;
            set_stream_policy(
                &mut stream_map,
                index,
                entitlement,
                action,
                subject,
                attribute,
                resource,
                family,
                transport,
                port,
                operator,
                modulo,
                value,
            )
        }
        Command::LoadExamples => {
            let mut static_map = open_static_policy(&cli.static_pin_path)?;
            load_example_static_policies(&mut static_map)
        }
        Command::LoadStreamExamples => {
            let mut stream_map = open_stream_policy(&cli.stream_pin_path)?;
            load_example_stream_policies(&mut stream_map)
        }
    }
}

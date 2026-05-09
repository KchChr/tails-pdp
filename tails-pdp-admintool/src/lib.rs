mod cli;
mod maps;
mod output;

use std::env;

use anyhow::{anyhow, bail};
use clap::{Parser, error::ErrorKind};
use tails_pdp_common::{
    ANY_SUBJECT, COMMAND_LEN, DEFCON_MAX_LEVEL, DEFCON_MIN_LEVEL, Entitlement,
    FileOpenStaticPolicy, FileOpenStreamPolicy, POLICY_BANK_SIZE, RESOURCE_LEN,
    SocketBindStaticPolicy, SocketBindStreamPolicy, SocketFamily, SocketTransport,
    policy_bank_offset,
};

use crate::{
    cli::{ActionArg, Cli, Command, print_usage},
    maps::{
        FileOpenStaticPolicyMap, FileOpenStreamPolicyMap, SocketBindStaticPolicyMap,
        SocketBindStreamPolicyMap, open_file_open_static_policies, open_file_open_stream_policies,
        open_policy_generation, open_socket_bind_static_policies, open_socket_bind_stream_policies,
    },
    output::{
        show_file_open_static, show_file_open_stream, show_socket_bind_static,
        show_socket_bind_stream,
    },
};

fn validate_stream_condition(
    attribute: cli::StreamAttributeArg,
    modulo: u64,
    value: u64,
) -> anyhow::Result<()> {
    if attribute != cli::StreamAttributeArg::Time && modulo != 0 {
        bail!("--modulo is only valid when --attribute time is used");
    }

    match attribute {
        cli::StreamAttributeArg::Time => {
            if modulo == 0 {
                bail!("--modulo must be > 0 when --attribute time is used");
            }
        }
        cli::StreamAttributeArg::Hour => {
            if value > 23 {
                bail!("hour value out of range: {} > 23", value);
            }
        }
        cli::StreamAttributeArg::Minute | cli::StreamAttributeArg::Second => {
            if value > 59 {
                bail!("time component value out of range: {} > 59", value);
            }
        }
        cli::StreamAttributeArg::Defcon => {
            if !((DEFCON_MIN_LEVEL as u64)..=(DEFCON_MAX_LEVEL as u64)).contains(&value) {
                bail!(
                    "DEFCON value out of range: {} is not in {}..={}",
                    value,
                    DEFCON_MIN_LEVEL,
                    DEFCON_MAX_LEVEL
                );
            }
        }
    }
    Ok(())
}

fn validate_len(name: &str, value: &str, max_len: usize) -> anyhow::Result<()> {
    if value.len() > max_len {
        bail!("{name} too long: {} > {}", value.len(), max_len);
    }
    Ok(())
}

fn ensure_privileges(command: &Command) -> anyhow::Result<()> {
    if command.requires_root() && unsafe { libc::geteuid() } != 0 {
        bail!("this command modifies pinned eBPF maps and must be run with sudo");
    }
    Ok(())
}

fn active_bank_offset(cli: &Cli) -> anyhow::Result<u32> {
    let generation_map = open_policy_generation(&cli.policy_generation_pin_path)?;
    let generation = generation_map
        .get(&0, 0)
        .map_err(anyhow::Error::from)
        .map_err(|error| anyhow!("failed to read POLICY_GENERATION[0]: {error}"))?;
    Ok(policy_bank_offset(generation))
}

fn map_index(bank_offset: u32, index: u32) -> anyhow::Result<u32> {
    if index >= POLICY_BANK_SIZE {
        bail!(
            "policy index {} out of range; max is {}",
            index,
            POLICY_BANK_SIZE - 1
        );
    }
    Ok(bank_offset + index)
}

fn clear_file_open_static_policy(
    map: &mut FileOpenStaticPolicyMap,
    index: u32,
    bank_offset: u32,
) -> anyhow::Result<()> {
    let index = map_index(bank_offset, index)?;
    map.set(index, FileOpenStaticPolicy::disabled(), 0)
        .map_err(anyhow::Error::from)
        .map_err(|error| anyhow!("failed to clear FILE_OPEN_STATIC_POLICIES[{index}]: {error}"))
}

fn clear_file_open_stream_policy(
    map: &mut FileOpenStreamPolicyMap,
    index: u32,
    bank_offset: u32,
) -> anyhow::Result<()> {
    let index = map_index(bank_offset, index)?;
    map.set(index, FileOpenStreamPolicy::disabled(), 0)
        .map_err(anyhow::Error::from)
        .map_err(|error| anyhow!("failed to clear FILE_OPEN_STREAM_POLICIES[{index}]: {error}"))
}

fn clear_all_file_open_static_policies(
    map: &mut FileOpenStaticPolicyMap,
    bank_offset: u32,
) -> anyhow::Result<()> {
    for index in 0..POLICY_BANK_SIZE {
        clear_file_open_static_policy(map, index, bank_offset)?;
    }
    Ok(())
}

fn clear_all_file_open_stream_policies(
    map: &mut FileOpenStreamPolicyMap,
    bank_offset: u32,
) -> anyhow::Result<()> {
    for index in 0..POLICY_BANK_SIZE {
        clear_file_open_stream_policy(map, index, bank_offset)?;
    }
    Ok(())
}

fn clear_socket_bind_static_policy(
    map: &mut SocketBindStaticPolicyMap,
    index: u32,
    bank_offset: u32,
) -> anyhow::Result<()> {
    if index >= POLICY_BANK_SIZE {
        bail!(
            "socket_bind static index {} out of range; max is {}",
            index,
            POLICY_BANK_SIZE - 1
        );
    }
    let index = map_index(bank_offset, index)?;
    map.set(index, SocketBindStaticPolicy::disabled(), 0)
        .map_err(anyhow::Error::from)
        .map_err(|error| anyhow!("failed to clear SOCKET_BIND_STATIC_POLICIES[{index}]: {error}"))
}

fn clear_socket_bind_stream_policy(
    map: &mut SocketBindStreamPolicyMap,
    index: u32,
    bank_offset: u32,
) -> anyhow::Result<()> {
    if index >= POLICY_BANK_SIZE {
        bail!(
            "socket_bind stream index {} out of range; max is {}",
            index,
            POLICY_BANK_SIZE - 1
        );
    }
    let index = map_index(bank_offset, index)?;
    map.set(index, SocketBindStreamPolicy::disabled(), 0)
        .map_err(anyhow::Error::from)
        .map_err(|error| anyhow!("failed to clear SOCKET_BIND_STREAM_POLICIES[{index}]: {error}"))
}

fn clear_all_socket_bind_static_policies(
    map: &mut SocketBindStaticPolicyMap,
    bank_offset: u32,
) -> anyhow::Result<()> {
    for index in 0..POLICY_BANK_SIZE {
        clear_socket_bind_static_policy(map, index, bank_offset)?;
    }
    Ok(())
}

fn clear_all_socket_bind_stream_policies(
    map: &mut SocketBindStreamPolicyMap,
    bank_offset: u32,
) -> anyhow::Result<()> {
    for index in 0..POLICY_BANK_SIZE {
        clear_socket_bind_stream_policy(map, index, bank_offset)?;
    }
    Ok(())
}

fn set_file_open_static_policy(
    map: &mut FileOpenStaticPolicyMap,
    index: u32,
    bank_offset: u32,
    entitlement: cli::EntitlementArg,
    subject: u32,
    command: String,
    resource: String,
) -> anyhow::Result<()> {
    let index = map_index(bank_offset, index)?;
    validate_len("command", &command, COMMAND_LEN)?;
    validate_len("resource", &resource, RESOURCE_LEN)?;

    let policy = FileOpenStaticPolicy::new(entitlement.into(), subject, &command, &resource)
        .resolve_resource_identity()
        .map_err(anyhow::Error::from)
        .map_err(|error| {
            anyhow!("failed to resolve FILE_OPEN_STATIC_POLICIES[{index}] resource: {error}")
        })?;

    map.set(index, policy, 0)
        .map_err(anyhow::Error::from)
        .map_err(|error| anyhow!("failed to write FILE_OPEN_STATIC_POLICIES[{index}]: {error}"))
}

fn set_socket_bind_static_policy(
    map: &mut SocketBindStaticPolicyMap,
    index: u32,
    bank_offset: u32,
    entitlement: cli::EntitlementArg,
    subject: u32,
    family: cli::SocketFamilyArg,
    transport: cli::SocketTransportArg,
    port: u16,
    resource: String,
) -> anyhow::Result<()> {
    let index = map_index(bank_offset, index)?;
    validate_len("resource", &resource, RESOURCE_LEN)?;

    let policy = SocketBindStaticPolicy::new(
        entitlement.into(),
        subject,
        family.into(),
        transport.into(),
        port,
        &resource,
    )
    .resolve_resource_identity()
    .map_err(anyhow::Error::from)
    .map_err(|error| {
        anyhow!("failed to resolve SOCKET_BIND_STATIC_POLICIES[{index}] resource: {error}")
    })?;

    map.set(index, policy, 0)
        .map_err(anyhow::Error::from)
        .map_err(|error| anyhow!("failed to write SOCKET_BIND_STATIC_POLICIES[{index}]: {error}"))
}

fn set_file_open_stream_policy(
    map: &mut FileOpenStreamPolicyMap,
    index: u32,
    bank_offset: u32,
    entitlement: cli::EntitlementArg,
    subject: u32,
    attribute: cli::StreamAttributeArg,
    resource: String,
    operator: cli::StreamOperatorArg,
    modulo: u64,
    value: u64,
) -> anyhow::Result<()> {
    let index = map_index(bank_offset, index)?;
    validate_len("resource", &resource, RESOURCE_LEN)?;
    validate_stream_condition(attribute, modulo, value)?;

    let mut policy = FileOpenStreamPolicy::time(
        entitlement.into(),
        subject,
        &resource,
        operator.into(),
        modulo,
        value,
    )
    .resolve_resource_identity()
    .map_err(anyhow::Error::from)
    .map_err(|error| {
        anyhow!("failed to resolve FILE_OPEN_STREAM_POLICIES[{index}] resource: {error}")
    })?;
    policy.attribute = attribute.into();

    map.set(index, policy, 0)
        .map_err(anyhow::Error::from)
        .map_err(|error| anyhow!("failed to write FILE_OPEN_STREAM_POLICIES[{index}]: {error}"))
}

fn set_socket_bind_stream_policy(
    map: &mut SocketBindStreamPolicyMap,
    index: u32,
    bank_offset: u32,
    entitlement: cli::EntitlementArg,
    subject: u32,
    attribute: cli::StreamAttributeArg,
    family: cli::SocketFamilyArg,
    transport: cli::SocketTransportArg,
    port: u16,
    resource: String,
    operator: cli::StreamOperatorArg,
    modulo: u64,
    value: u64,
) -> anyhow::Result<()> {
    let index = map_index(bank_offset, index)?;
    validate_len("resource", &resource, RESOURCE_LEN)?;
    validate_stream_condition(attribute, modulo, value)?;

    let mut policy = SocketBindStreamPolicy::time(
        entitlement.into(),
        subject,
        family.into(),
        transport.into(),
        port,
        &resource,
        operator.into(),
        modulo,
        value,
    )
    .resolve_resource_identity()
    .map_err(anyhow::Error::from)
    .map_err(|error| {
        anyhow!("failed to resolve SOCKET_BIND_STREAM_POLICIES[{index}] resource: {error}")
    })?;
    policy.attribute = attribute.into();

    map.set(index, policy, 0)
        .map_err(anyhow::Error::from)
        .map_err(|error| anyhow!("failed to write SOCKET_BIND_STREAM_POLICIES[{index}]: {error}"))
}

fn load_example_static_policies(
    file_open_map: &mut FileOpenStaticPolicyMap,
    socket_bind_map: &mut SocketBindStaticPolicyMap,
    bank_offset: u32,
) -> anyhow::Result<()> {
    for logical_index in 0..POLICY_BANK_SIZE {
        let index = bank_offset + logical_index;
        file_open_map
            .set(index, FileOpenStaticPolicy::disabled(), 0)
            .map_err(anyhow::Error::from)
            .map_err(|error| {
                anyhow!("failed to clear FILE_OPEN_STATIC_POLICIES[{index}]: {error}")
            })?;
    }
    for logical_index in 0..POLICY_BANK_SIZE {
        let index = bank_offset + logical_index;
        socket_bind_map
            .set(index, SocketBindStaticPolicy::disabled(), 0)
            .map_err(anyhow::Error::from)
            .map_err(|error| {
                anyhow!("failed to clear SOCKET_BIND_STATIC_POLICIES[{index}]: {error}")
            })?;
    }

    let file_open_examples = [FileOpenStaticPolicy::new(
        Entitlement::Deny,
        ANY_SUBJECT,
        "cat",
        "/etc/shadow",
    )];
    let socket_bind_examples = [SocketBindStaticPolicy::new(
        Entitlement::Deny,
        1000,
        SocketFamily::Inet,
        SocketTransport::Tcp,
        8080,
        "0.0.0.0",
    )];

    for (index, policy) in file_open_examples.into_iter().enumerate() {
        let policy = policy
            .resolve_resource_identity()
            .map_err(anyhow::Error::from)?;
        file_open_map
            .set(bank_offset + index as u32, policy, 0)
            .map_err(anyhow::Error::from)
            .map_err(|error| {
                anyhow!("failed to write FILE_OPEN_STATIC_POLICIES[{index}]: {error}")
            })?;
    }

    for (index, policy) in socket_bind_examples.into_iter().enumerate() {
        let policy = policy
            .resolve_resource_identity()
            .map_err(anyhow::Error::from)?;
        socket_bind_map
            .set(bank_offset + index as u32, policy, 0)
            .map_err(anyhow::Error::from)
            .map_err(|error| {
                anyhow!("failed to write SOCKET_BIND_STATIC_POLICIES[{index}]: {error}")
            })?;
    }

    Ok(())
}

fn load_example_stream_policies(
    file_open_map: &mut FileOpenStreamPolicyMap,
    socket_bind_map: &mut SocketBindStreamPolicyMap,
    bank_offset: u32,
) -> anyhow::Result<()> {
    for logical_index in 0..POLICY_BANK_SIZE {
        let index = bank_offset + logical_index;
        file_open_map
            .set(index, FileOpenStreamPolicy::disabled(), 0)
            .map_err(anyhow::Error::from)
            .map_err(|error| {
                anyhow!("failed to clear FILE_OPEN_STREAM_POLICIES[{index}]: {error}")
            })?;
    }
    for logical_index in 0..POLICY_BANK_SIZE {
        let index = bank_offset + logical_index;
        socket_bind_map
            .set(index, SocketBindStreamPolicy::disabled(), 0)
            .map_err(anyhow::Error::from)
            .map_err(|error| {
                anyhow!("failed to clear SOCKET_BIND_STREAM_POLICIES[{index}]: {error}")
            })?;
    }

    let file_open_examples = [FileOpenStreamPolicy::time(
        Entitlement::Permit,
        1000,
        "/home/hntr/test.txt",
        tails_pdp_common::StreamOperator::LessThan,
        10,
        5,
    )];
    let socket_bind_examples = [SocketBindStreamPolicy::time(
        Entitlement::Permit,
        1000,
        SocketFamily::Inet,
        SocketTransport::Tcp,
        8080,
        "0.0.0.0",
        tails_pdp_common::StreamOperator::LessThan,
        10,
        5,
    )];

    for (index, policy) in file_open_examples.into_iter().enumerate() {
        let policy = policy
            .resolve_resource_identity()
            .map_err(anyhow::Error::from)?;
        file_open_map
            .set(bank_offset + index as u32, policy, 0)
            .map_err(anyhow::Error::from)
            .map_err(|error| {
                anyhow!("failed to write FILE_OPEN_STREAM_POLICIES[{index}]: {error}")
            })?;
    }

    for (index, policy) in socket_bind_examples.into_iter().enumerate() {
        let policy = policy
            .resolve_resource_identity()
            .map_err(anyhow::Error::from)?;
        socket_bind_map
            .set(bank_offset + index as u32, policy, 0)
            .map_err(anyhow::Error::from)
            .map_err(|error| {
                anyhow!("failed to write SOCKET_BIND_STREAM_POLICIES[{index}]: {error}")
            })?;
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
    let bank_offset = active_bank_offset(&cli)?;

    match cli.command {
        Command::Show => {
            let file_open_static = open_file_open_static_policies(&cli.file_open_static_pin_path)?;
            let file_open_stream = open_file_open_stream_policies(&cli.file_open_stream_pin_path)?;
            let socket_bind_static =
                open_socket_bind_static_policies(&cli.socket_bind_static_pin_path)?;
            let socket_bind_stream =
                open_socket_bind_stream_policies(&cli.socket_bind_stream_pin_path)?;
            show_file_open_static(&file_open_static, bank_offset, false)?;
            show_file_open_stream(&file_open_stream, bank_offset, false)?;
            show_socket_bind_static(&socket_bind_static, bank_offset, false)?;
            show_socket_bind_stream(&socket_bind_stream, bank_offset, false)
        }
        Command::ShowActive => {
            let file_open_static = open_file_open_static_policies(&cli.file_open_static_pin_path)?;
            let file_open_stream = open_file_open_stream_policies(&cli.file_open_stream_pin_path)?;
            let socket_bind_static =
                open_socket_bind_static_policies(&cli.socket_bind_static_pin_path)?;
            let socket_bind_stream =
                open_socket_bind_stream_policies(&cli.socket_bind_stream_pin_path)?;
            show_file_open_static(&file_open_static, bank_offset, true)?;
            show_file_open_stream(&file_open_stream, bank_offset, true)?;
            show_socket_bind_static(&socket_bind_static, bank_offset, true)?;
            show_socket_bind_stream(&socket_bind_stream, bank_offset, true)
        }
        Command::ClearAll { action } => match action {
            None => {
                let mut file_open_static =
                    open_file_open_static_policies(&cli.file_open_static_pin_path)?;
                let mut file_open_stream =
                    open_file_open_stream_policies(&cli.file_open_stream_pin_path)?;
                let mut socket_bind_static =
                    open_socket_bind_static_policies(&cli.socket_bind_static_pin_path)?;
                let mut socket_bind_stream =
                    open_socket_bind_stream_policies(&cli.socket_bind_stream_pin_path)?;

                clear_all_file_open_static_policies(&mut file_open_static, bank_offset)?;
                clear_all_file_open_stream_policies(&mut file_open_stream, bank_offset)?;
                clear_all_socket_bind_static_policies(&mut socket_bind_static, bank_offset)?;
                clear_all_socket_bind_stream_policies(&mut socket_bind_stream, bank_offset)
            }
            Some(ActionArg::FileOpen) => {
                let mut file_open_static =
                    open_file_open_static_policies(&cli.file_open_static_pin_path)?;
                let mut file_open_stream =
                    open_file_open_stream_policies(&cli.file_open_stream_pin_path)?;
                clear_all_file_open_static_policies(&mut file_open_static, bank_offset)?;
                clear_all_file_open_stream_policies(&mut file_open_stream, bank_offset)
            }
            Some(ActionArg::SocketBind) => {
                let mut socket_bind_static =
                    open_socket_bind_static_policies(&cli.socket_bind_static_pin_path)?;
                let mut socket_bind_stream =
                    open_socket_bind_stream_policies(&cli.socket_bind_stream_pin_path)?;
                clear_all_socket_bind_static_policies(&mut socket_bind_static, bank_offset)?;
                clear_all_socket_bind_stream_policies(&mut socket_bind_stream, bank_offset)
            }
        },
        Command::Clear { index, action } => match action {
            ActionArg::FileOpen => {
                let mut map = open_file_open_static_policies(&cli.file_open_static_pin_path)?;
                clear_file_open_static_policy(&mut map, index, bank_offset)
            }
            ActionArg::SocketBind => {
                let mut map = open_socket_bind_static_policies(&cli.socket_bind_static_pin_path)?;
                clear_socket_bind_static_policy(&mut map, index, bank_offset)
            }
        },
        Command::ClearStream { index, action } => match action {
            ActionArg::FileOpen => {
                let mut map = open_file_open_stream_policies(&cli.file_open_stream_pin_path)?;
                clear_file_open_stream_policy(&mut map, index, bank_offset)
            }
            ActionArg::SocketBind => {
                let mut map = open_socket_bind_stream_policies(&cli.socket_bind_stream_pin_path)?;
                clear_socket_bind_stream_policy(&mut map, index, bank_offset)
            }
        },
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
        } => match action {
            ActionArg::FileOpen => {
                let mut map = open_file_open_static_policies(&cli.file_open_static_pin_path)?;
                set_file_open_static_policy(
                    &mut map,
                    index,
                    bank_offset,
                    entitlement,
                    subject,
                    command,
                    resource,
                )
            }
            ActionArg::SocketBind => {
                let mut map = open_socket_bind_static_policies(&cli.socket_bind_static_pin_path)?;
                set_socket_bind_static_policy(
                    &mut map,
                    index,
                    bank_offset,
                    entitlement,
                    subject,
                    family,
                    transport,
                    port,
                    resource,
                )
            }
        },
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
        } => match action {
            ActionArg::FileOpen => {
                let mut map = open_file_open_stream_policies(&cli.file_open_stream_pin_path)?;
                set_file_open_stream_policy(
                    &mut map,
                    index,
                    bank_offset,
                    entitlement,
                    subject,
                    attribute,
                    resource,
                    operator,
                    modulo,
                    value,
                )
            }
            ActionArg::SocketBind => {
                let mut map = open_socket_bind_stream_policies(&cli.socket_bind_stream_pin_path)?;
                set_socket_bind_stream_policy(
                    &mut map,
                    index,
                    bank_offset,
                    entitlement,
                    subject,
                    attribute,
                    family,
                    transport,
                    port,
                    resource,
                    operator,
                    modulo,
                    value,
                )
            }
        },
        Command::LoadExamples => {
            let mut file_open_map = open_file_open_static_policies(&cli.file_open_static_pin_path)?;
            let mut socket_bind_map =
                open_socket_bind_static_policies(&cli.socket_bind_static_pin_path)?;
            load_example_static_policies(&mut file_open_map, &mut socket_bind_map, bank_offset)
        }
        Command::LoadStreamExamples => {
            let mut file_open_map = open_file_open_stream_policies(&cli.file_open_stream_pin_path)?;
            let mut socket_bind_map =
                open_socket_bind_stream_policies(&cli.socket_bind_stream_pin_path)?;
            load_example_stream_policies(&mut file_open_map, &mut socket_bind_map, bank_offset)
        }
    }
}

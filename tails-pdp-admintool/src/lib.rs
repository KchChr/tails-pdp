mod cli;
mod maps;
mod output;

use std::{
    collections::HashMap,
    env, fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, anyhow};
use clap::{Parser, error::ErrorKind};
use tails_pdp_common::{AttributeHash, attribute_bank, attribute_hash, policy_bank_offset};

use crate::{
    cli::{Cli, Command},
    maps::{
        open_attribute_generation, open_attributes, open_file_open_static_policies,
        open_file_open_stream_policies, open_policy_generation,
    },
    output::{HashDictionary, show_attributes, show_file_open_static, show_file_open_stream},
};

fn read_generation(map_path: &PathBuf, label: &str) -> anyhow::Result<u32> {
    let map = match label {
        "POLICY_GENERATION" => open_policy_generation(map_path)?,
        "ATTRIBUTE_GENERATION" => open_attribute_generation(map_path)?,
        _ => unreachable!("unsupported generation map"),
    };
    map.get(&0, 0)
        .map_err(anyhow::Error::from)
        .map_err(|error| anyhow!("failed to read {label}[0]: {error}"))
}

fn hash_key(hash: AttributeHash) -> (u64, u64) {
    (hash.low, hash.high)
}

fn remember(dictionary: &mut HashDictionary, value: &str) {
    if value.is_empty() {
        return;
    }
    dictionary
        .entry(hash_key(attribute_hash(value)))
        .or_insert_with(|| value.to_string());
}

fn build_hash_dictionary(
    policy_dir: &Path,
    environment_dir: &Path,
) -> anyhow::Result<HashDictionary> {
    let mut dictionary = HashMap::new();
    collect_environment_dictionary(environment_dir, &mut dictionary)?;
    collect_policy_dictionary(policy_dir, &mut dictionary)?;
    Ok(dictionary)
}

fn collect_environment_dictionary(
    environment_dir: &Path,
    dictionary: &mut HashDictionary,
) -> anyhow::Result<()> {
    let system_path = environment_dir.join("system.env");
    if system_path.exists() {
        collect_env_file_dictionary(&system_path, dictionary)?;
    }

    let subjects_dir = environment_dir.join("subjects");
    if let Ok(entries) = fs::read_dir(&subjects_dir) {
        for entry in entries {
            let entry =
                entry.with_context(|| format!("failed to read '{}'", subjects_dir.display()))?;
            let path = entry.path();
            if path.is_file() {
                collect_env_file_dictionary(&path, dictionary)?;
            }
        }
    }

    let resources_dir = environment_dir.join("resources");
    if resources_dir.exists() {
        collect_env_dictionary_recursive(&resources_dir, dictionary)?;
    }

    Ok(())
}

fn collect_env_dictionary_recursive(
    directory: &Path,
    dictionary: &mut HashDictionary,
) -> anyhow::Result<()> {
    let entries = fs::read_dir(directory)
        .with_context(|| format!("failed to read '{}'", directory.display()))?;
    for entry in entries {
        let entry = entry.with_context(|| format!("failed to read '{}'", directory.display()))?;
        let path = entry.path();
        if path.is_dir() {
            collect_env_dictionary_recursive(&path, dictionary)?;
        } else if path.extension().and_then(|extension| extension.to_str()) == Some("env") {
            collect_env_file_dictionary(&path, dictionary)?;
        }
    }
    Ok(())
}

fn collect_env_file_dictionary(path: &Path, dictionary: &mut HashDictionary) -> anyhow::Result<()> {
    let source =
        fs::read_to_string(path).with_context(|| format!("failed to read '{}'", path.display()))?;
    for line in source.lines() {
        let trimmed = strip_comment(line).trim();
        if trimmed.is_empty() {
            continue;
        }
        let Some((name, value)) = trimmed.split_once('=') else {
            continue;
        };
        remember(dictionary, name.trim());
        remember_attribute_value(dictionary, value.trim());
    }
    Ok(())
}

fn collect_policy_dictionary(
    policy_dir: &Path,
    dictionary: &mut HashDictionary,
) -> anyhow::Result<()> {
    if !policy_dir.exists() {
        return Ok(());
    }
    collect_policy_dictionary_recursive(policy_dir, dictionary)
}

fn collect_policy_dictionary_recursive(
    directory: &Path,
    dictionary: &mut HashDictionary,
) -> anyhow::Result<()> {
    let entries = fs::read_dir(directory)
        .with_context(|| format!("failed to read '{}'", directory.display()))?;
    for entry in entries {
        let entry = entry.with_context(|| format!("failed to read '{}'", directory.display()))?;
        let path = entry.path();
        if path.is_dir() {
            collect_policy_dictionary_recursive(&path, dictionary)?;
        } else if path.extension().and_then(|extension| extension.to_str()) == Some("sapl") {
            collect_policy_file_dictionary(&path, dictionary)?;
        }
    }
    Ok(())
}

fn collect_policy_file_dictionary(
    path: &Path,
    dictionary: &mut HashDictionary,
) -> anyhow::Result<()> {
    let source =
        fs::read_to_string(path).with_context(|| format!("failed to read '{}'", path.display()))?;
    for line in source.lines() {
        let statement = strip_comment(line).trim().trim_end_matches(';').trim();
        if statement.is_empty() {
            continue;
        }
        collect_dynamic_attribute_statement(statement, "subject.", dictionary);
        collect_dynamic_attribute_statement(statement, "system.", dictionary);
        collect_dynamic_attribute_statement(statement, "resource.", dictionary);
        for quoted in quoted_strings(statement) {
            remember(dictionary, &quoted);
        }
    }
    Ok(())
}

fn collect_dynamic_attribute_statement(
    statement: &str,
    prefix: &str,
    dictionary: &mut HashDictionary,
) {
    let Some(start) = statement.find(prefix) else {
        return;
    };
    let remainder = &statement[start + prefix.len()..];
    let attribute_name: String = remainder
        .chars()
        .take_while(|character| {
            character.is_ascii_alphanumeric() || *character == '_' || *character == '-'
        })
        .collect();
    if attribute_name.is_empty()
        || matches!(
            attribute_name.as_str(),
            "uid" | "path" | "family" | "transport" | "ip" | "port"
        )
    {
        return;
    }
    remember(dictionary, &attribute_name);
}

fn remember_attribute_value(dictionary: &mut HashDictionary, raw: &str) {
    let trimmed = raw.trim();
    if trimmed.starts_with('"') && trimmed.ends_with('"') && trimmed.len() >= 2 {
        remember(dictionary, &trimmed[1..trimmed.len() - 1]);
    }
}

fn quoted_strings(statement: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut remaining = statement;
    while let Some(start) = remaining.find('"') {
        let after_start = &remaining[start + 1..];
        let Some(end) = after_start.find('"') else {
            break;
        };
        values.push(after_start[..end].to_string());
        remaining = &after_start[end + 1..];
    }
    values
}

fn strip_comment(line: &str) -> &str {
    let slash_comment = line.find("//");
    let hash_comment = line.find('#');
    match (slash_comment, hash_comment) {
        (Some(left), Some(right)) => &line[..left.min(right)],
        (Some(index), None) | (None, Some(index)) => &line[..index],
        (None, None) => line,
    }
}

fn print_usage() {
    println!("tails-pdp-admintool");
    println!();
    println!("Liest die aktuell geladenen file_open Policies und dynamischen Attribute.");
    println!();
    println!("USAGE:");
    println!("  tails-pdp-admintool <COMMAND> [OPTIONS]");
    println!();
    println!("COMMANDS:");
    println!("  show             Zeigt aktive Bank, Policies und Attribute.");
    println!("  show-active      Zeigt nur aktive Policies sowie Attribute.");
    println!("  show-policies    Zeigt Policies.");
    println!("  show-attributes  Zeigt Attribute.");
    println!();
    println!("OPTIONS:");
    println!("  --file-open-static-pin-path <PFAD>");
    println!("  --file-open-stream-pin-path <PFAD>");
    println!("  --policy-generation-pin-path <PFAD>");
    println!("  --attribute-generation-pin-path <PFAD>");
    println!("  --attributes-pin-path <PFAD>");
    println!("  --policy-dir <PFAD>       Quelle fuer Hash-Namen, Standard: policies");
    println!("  --environment-dir <PFAD>  Quelle fuer Hash-Namen, Standard: environment");
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

    let policy_generation = read_generation(&cli.policy_generation_pin_path, "POLICY_GENERATION")?;
    let policy_bank_offset = policy_bank_offset(policy_generation);
    let attribute_generation =
        read_generation(&cli.attribute_generation_pin_path, "ATTRIBUTE_GENERATION")?;
    let attribute_bank = attribute_bank(attribute_generation);
    let dictionary = build_hash_dictionary(&cli.policy_dir, &cli.environment_dir)?;

    println!(
        "generation policy={} policy_bank_offset={} attribute={} attribute_bank={}",
        policy_generation, policy_bank_offset, attribute_generation, attribute_bank
    );
    println!();

    match cli.command {
        Command::Show => {
            show_policies(&cli, policy_bank_offset, false, &dictionary)?;
            show_attribute_map(&cli, attribute_bank, &dictionary)
        }
        Command::ShowActive => {
            show_policies(&cli, policy_bank_offset, true, &dictionary)?;
            show_attribute_map(&cli, attribute_bank, &dictionary)
        }
        Command::ShowPolicies => show_policies(&cli, policy_bank_offset, false, &dictionary),
        Command::ShowAttributes => show_attribute_map(&cli, attribute_bank, &dictionary),
    }
}

fn show_policies(
    cli: &Cli,
    policy_bank_offset: u32,
    active_only: bool,
    dictionary: &HashDictionary,
) -> anyhow::Result<()> {
    let file_open_static = open_file_open_static_policies(&cli.file_open_static_pin_path)?;
    let file_open_stream = open_file_open_stream_policies(&cli.file_open_stream_pin_path)?;
    show_file_open_static(&file_open_static, policy_bank_offset, active_only)?;
    show_file_open_stream(
        &file_open_stream,
        policy_bank_offset,
        active_only,
        dictionary,
    )
}

fn show_attribute_map(
    cli: &Cli,
    attribute_bank: u32,
    dictionary: &HashDictionary,
) -> anyhow::Result<()> {
    let attributes = open_attributes(&cli.attributes_pin_path)?;
    show_attributes(&attributes, attribute_bank, dictionary)
}

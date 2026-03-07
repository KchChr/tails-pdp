use std::{
    env,
    io::{self, Write},
    process::Command,
    thread,
    time::{Duration, SystemTime},
};

use anyhow::{Context, Result, bail};
use serde_json::Value;

#[derive(Debug)]
enum Commands {
    /// List available eBPF maps with IDs and metadata
    Maps,
    /// Dump one map by ID
    Dump {
        /// Map ID from `maps`
        id: u32,
        /// Refresh output continuously
        live: bool,
        /// Refresh interval for live mode
        interval_ms: u64,
        /// Print raw bytes instead of decoded output
        raw: bool,
    },
}

#[derive(Debug, Clone)]
struct MapInfo {
    id: u32,
    name: String,
    map_type: String,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
}

#[derive(Debug)]
struct MapEntry {
    key: Vec<u8>,
    value: Vec<u8>,
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().skip(1).collect();
    let command = match parse_cli_args(&args) {
        ParseResult::Command(command) => command,
        ParseResult::Help => {
            print_usage();
            return Ok(());
        }
        ParseResult::Error(msg) => {
            eprintln!("error: {msg}");
            eprintln!();
            print_usage();
            std::process::exit(2);
        }
    };

    match command {
        Commands::Maps => {
            let mut maps = fetch_maps()?;
            maps.sort_by_key(|m| m.id);
            print_maps(&maps);
        }
        Commands::Dump {
            id,
            live,
            interval_ms,
            raw,
        } => {
            if live {
                let interval = Duration::from_millis(interval_ms.max(100));
                loop {
                    clear_screen()?;
                    println!("tails-pdp-admin live dump @ {:?}", SystemTime::now());
                    dump_once(id, raw)?;
                    io::stdout().flush().context("flush stdout")?;
                    thread::sleep(interval);
                }
            } else {
                dump_once(id, raw)?;
            }
        }
    }

    Ok(())
}

enum ParseResult {
    Command(Commands),
    Help,
    Error(String),
}

fn parse_cli_args(args: &[String]) -> ParseResult {
    if args.is_empty() {
        return ParseResult::Help;
    }
    if args.iter().any(|arg| arg == "-h" || arg == "--help") {
        return ParseResult::Help;
    }

    match args[0].as_str() {
        "maps" => {
            if args.len() == 1 {
                ParseResult::Command(Commands::Maps)
            } else {
                ParseResult::Error(format!("unexpected argument for maps: '{}'", args[1]))
            }
        }
        "dump" => parse_dump_args(&args[1..]),
        other => ParseResult::Error(format!("unrecognized subcommand '{other}'")),
    }
}

fn parse_dump_args(args: &[String]) -> ParseResult {
    let mut id: Option<u32> = None;
    let mut live = false;
    let mut interval_ms: u64 = 1000;
    let mut raw = false;
    let mut i = 0usize;

    while i < args.len() {
        match args[i].as_str() {
            "--id" => {
                if i + 1 >= args.len() {
                    return ParseResult::Error("missing value for --id".to_owned());
                }
                let parsed_id = match args[i + 1].parse::<u32>() {
                    Ok(v) => v,
                    Err(_) => {
                        return ParseResult::Error(format!(
                            "invalid value '{}' for --id (expected u32)",
                            args[i + 1]
                        ));
                    }
                };
                id = Some(parsed_id);
                i += 2;
            }
            "--live" => {
                live = true;
                i += 1;
            }
            "--interval-ms" => {
                if i + 1 >= args.len() {
                    return ParseResult::Error("missing value for --interval-ms".to_owned());
                }
                let parsed_interval = match args[i + 1].parse::<u64>() {
                    Ok(v) => v,
                    Err(_) => {
                        return ParseResult::Error(format!(
                            "invalid value '{}' for --interval-ms (expected u64)",
                            args[i + 1]
                        ));
                    }
                };
                interval_ms = parsed_interval.max(100);
                i += 2;
            }
            "--raw" => {
                raw = true;
                i += 1;
            }
            other => {
                return ParseResult::Error(format!("unrecognized argument '{other}' for dump"));
            }
        }
    }

    match id {
        Some(id) => ParseResult::Command(Commands::Dump {
            id,
            live,
            interval_ms,
            raw,
        }),
        None => ParseResult::Error("missing required argument --id <MAP_ID>".to_owned()),
    }
}

fn dump_once(id: u32, raw: bool) -> Result<()> {
    let map_info = fetch_maps()?.into_iter().find(|m| m.id == id);
    let entries = fetch_map_entries(id)?;

    if let Some(info) = &map_info {
        println!(
            "map id={} name={} type={} key={}B value={}B max_entries={}",
            info.id, info.name, info.map_type, info.key_size, info.value_size, info.max_entries
        );
    } else {
        println!("map id={} (metadata not found in `bpftool map show`)", id);
    }

    println!("entries={}", entries.len());
    for (index, entry) in entries.iter().enumerate() {
        if !raw && looks_like_authz_subscription(entry) {
            print_authz_entry(index, entry);
        } else if !raw && entry.key.len() == 4 && entry.value.len() == 4 {
            print_i32_entry(index, entry);
        } else {
            print_raw_entry(index, entry);
        }
    }

    Ok(())
}

fn looks_like_authz_subscription(entry: &MapEntry) -> bool {
    entry.key.len() == 8 && entry.value.len() >= 28
}

fn print_authz_entry(index: usize, entry: &MapEntry) {
    let key_pid = le_u32(&entry.key, 0).unwrap_or_default();
    let key_tgid = le_u32(&entry.key, 4).unwrap_or_default();
    let subject_uid = le_u32(&entry.value, 0).unwrap_or_default();
    let subject_gid = le_u32(&entry.value, 4).unwrap_or_default();
    let action = entry.value[8];
    let pid = le_u32(&entry.value, 12).unwrap_or_default();
    let tgid = le_u32(&entry.value, 16).unwrap_or_default();
    let resource_id = le_u64(&entry.value, 20).unwrap_or_default();

    println!(
        "#{index:04} key(pid={key_pid},tgid={key_tgid}) subject(uid={subject_uid},gid={subject_gid}) action={action} request(pid={pid},tgid={tgid}) resource_id={resource_id}"
    );
}

fn print_i32_entry(index: usize, entry: &MapEntry) {
    let key = le_u32(&entry.key, 0).unwrap_or_default();
    let value = le_i32(&entry.value, 0).unwrap_or_default();
    println!("#{index:04} key={key} value={value}");
}

fn print_raw_entry(index: usize, entry: &MapEntry) {
    println!(
        "#{index:04} key=[{}] value=[{}]",
        hex_bytes(&entry.key),
        hex_bytes(&entry.value)
    );
}

fn print_maps(maps: &[MapInfo]) {
    println!(
        "{:<6} {:<16} {:<12} {:>6} {:>8} {:>12}",
        "ID", "NAME", "TYPE", "KEY", "VALUE", "MAX_ENTRIES"
    );
    for map in maps {
        println!(
            "{:<6} {:<16} {:<12} {:>6} {:>8} {:>12}",
            map.id,
            map.name,
            map.map_type,
            format!("{}B", map.key_size),
            format!("{}B", map.value_size),
            map.max_entries
        );
    }
}

fn fetch_maps() -> Result<Vec<MapInfo>> {
    let value = run_bpftool_json(&["map", "show"])?;
    let maps = as_array(&value).context("unexpected JSON for `bpftool map show`")?;
    let mut out = Vec::new();

    for item in maps {
        let Some(obj) = item.as_object() else {
            continue;
        };
        let Some(id) = obj.get("id").and_then(parse_u32) else {
            continue;
        };

        let name = obj
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("<unknown>")
            .to_owned();
        let map_type = obj
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or("<unknown>")
            .to_owned();
        let key_size = obj.get("key").and_then(parse_u32).unwrap_or_default();
        let value_size = obj.get("value").and_then(parse_u32).unwrap_or_default();
        let max_entries = obj
            .get("max_entries")
            .and_then(parse_u32)
            .unwrap_or_default();

        out.push(MapInfo {
            id,
            name,
            map_type,
            key_size,
            value_size,
            max_entries,
        });
    }

    Ok(out)
}

fn fetch_map_entries(id: u32) -> Result<Vec<MapEntry>> {
    let id_arg = id.to_string();
    let value = run_bpftool_json(&["map", "dump", "id", id_arg.as_str()])?;
    let items = as_array(&value).context("unexpected JSON for `bpftool map dump`")?;
    let mut entries = Vec::new();

    for item in items {
        let Some(obj) = item.as_object() else {
            continue;
        };
        let key = obj
            .get("key")
            .and_then(parse_byte_array)
            .context("failed to parse map key bytes")?;
        let value = obj
            .get("value")
            .and_then(parse_byte_array)
            .context("failed to parse map value bytes")?;

        entries.push(MapEntry { key, value });
    }

    Ok(entries)
}

fn run_bpftool_json(args: &[&str]) -> Result<Value> {
    let output = Command::new("bpftool")
        .arg("-j")
        .args(args)
        .output()
        .with_context(|| {
            format!(
                "failed to run `bpftool -j {}` (is bpftool installed?)",
                args.join(" ")
            )
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        bail!(
            "bpftool failed for `{}`\nstderr: {}\nstdout: {}\nHint: try running this tool with sudo.",
            args.join(" "),
            stderr.trim(),
            stdout.trim()
        );
    }

    serde_json::from_slice::<Value>(&output.stdout)
        .with_context(|| format!("failed to parse JSON from `bpftool -j {}`", args.join(" ")))
}

fn parse_u32(value: &Value) -> Option<u32> {
    if let Some(n) = value.as_u64() {
        return u32::try_from(n).ok();
    }
    let s = value.as_str()?.trim();
    if let Ok(n) = s.parse::<u32>() {
        return Some(n);
    }
    let hex = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X"))?;
    u32::from_str_radix(hex, 16).ok()
}

fn parse_byte_array(value: &Value) -> Option<Vec<u8>> {
    let arr = if let Some(arr) = value.as_array() {
        arr
    } else {
        value.get("bytes")?.as_array()?
    };
    let mut out = Vec::with_capacity(arr.len());

    for item in arr {
        let byte = parse_u8(item)?;
        out.push(byte);
    }

    Some(out)
}

fn parse_u8(value: &Value) -> Option<u8> {
    if let Some(n) = value.as_u64() {
        return u8::try_from(n).ok();
    }

    let s = value.as_str()?.trim();
    if let Ok(n) = s.parse::<u16>() {
        return u8::try_from(n).ok();
    }
    let hex = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    u8::from_str_radix(hex, 16).ok()
}

fn as_array(value: &Value) -> Option<&Vec<Value>> {
    if let Some(arr) = value.as_array() {
        return Some(arr);
    }
    value
        .get("maps")
        .and_then(Value::as_array)
        .or_else(|| value.get("entries").and_then(Value::as_array))
}

fn le_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let data: [u8; 4] = bytes.get(offset..offset + 4)?.try_into().ok()?;
    Some(u32::from_le_bytes(data))
}

fn le_i32(bytes: &[u8], offset: usize) -> Option<i32> {
    let data: [u8; 4] = bytes.get(offset..offset + 4)?.try_into().ok()?;
    Some(i32::from_le_bytes(data))
}

fn le_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    let data: [u8; 8] = bytes.get(offset..offset + 8)?.try_into().ok()?;
    Some(u64::from_le_bytes(data))
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn clear_screen() -> Result<()> {
    print!("\x1B[2J\x1B[H");
    io::stdout().flush().context("flush stdout")
}

fn print_usage() {
    println!("Usage:");
    println!("  tails-pdp-admin maps");
    println!("  tails-pdp-admin dump --id <MAP_ID> [--live] [--interval-ms <MS>] [--raw]");
    println!();
    println!("Commands:");
    println!("  maps    List available eBPF maps with IDs and metadata");
    println!("  dump    Dump one map by ID");
    println!();
    println!("Examples:");
    println!("  tails-pdp-admin maps");
    println!("  tails-pdp-admin dump --id 3433");
    println!("  tails-pdp-admin dump --id 3433 --live --interval-ms 1000");
}

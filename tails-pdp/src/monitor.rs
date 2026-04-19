use std::{
    collections::{HashMap, HashSet},
    fs, io,
    mem::MaybeUninit,
    net::{Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::Context;
use aya::maps::{Array, Map, MapData};
use tails_pdp_common::{
    Entitlement, Iso8601TimeParts, SOCKET_BIND_STATIC_POLICY_MAX_ENTRIES,
    SOCKET_BIND_STREAM_POLICY_MAX_ENTRIES, SOCKET_IP_LEN, SocketBindRequest,
    SocketBindStaticPolicy, SocketBindStreamPolicy, SocketFamily, SocketTransport,
    evaluate_socket_bind_static_policy, evaluate_socket_bind_stream_policy,
};
use tokio::time;

use crate::BPF_PIN_DIRECTORY;

type SocketBindStaticPolicyMap = Array<MapData, SocketBindStaticPolicy>;
type SocketBindStreamPolicyMap = Array<MapData, SocketBindStreamPolicy>;

#[derive(Clone, Debug)]
struct ActiveSocket {
    family: SocketFamily,
    transport: SocketTransport,
    ip: [u8; SOCKET_IP_LEN],
    port: u16,
    uid: u32,
    inode: u64,
}

#[derive(Clone, Debug)]
struct ProcessInfo {
    pid: u32,
    uid: u32,
    command: String,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct ViolationKey {
    policy_kind: PolicyKind,
    policy_index: u32,
    pid: u32,
    socket_inode: u64,
}

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
enum PolicyKind {
    Static,
    Stream,
}

struct Violation {
    key: ViolationKey,
    subject: u32,
    command: String,
    family: SocketFamily,
    transport: SocketTransport,
    ip: [u8; SOCKET_IP_LEN],
    port: u16,
}

pub async fn run_socket_bind_monitor() -> anyhow::Result<()> {
    let mut static_policies = open_socket_bind_static_policies()?;
    let mut stream_policies = open_socket_bind_stream_policies()?;
    let mut previous_violations = HashSet::new();
    let mut interval = time::interval(Duration::from_secs(1));

    loop {
        interval.tick().await;

        match collect_socket_bind_violations(&mut static_policies, &mut stream_policies) {
            Ok(current_violations) => {
                let mut current_keys = HashSet::new();
                for violation in current_violations {
                    let first_seen_in_scan = current_keys.insert(violation.key.clone());
                    if !first_seen_in_scan {
                        continue;
                    }
                    if !previous_violations.contains(&violation.key) {
                        print_violation(&violation);
                    }
                    enforce_violation(&violation);
                }
                previous_violations = current_keys;
            }
            Err(error) => {
                eprintln!("MONITOR socket_bind scan failed: {error:#}");
            }
        }
    }
}

fn open_socket_bind_static_policies() -> anyhow::Result<SocketBindStaticPolicyMap> {
    open_array_map(
        &Path::new(BPF_PIN_DIRECTORY).join("SOCKET_BIND_STATIC_POLICIES"),
        "SOCKET_BIND_STATIC_POLICIES",
    )
}

fn open_socket_bind_stream_policies() -> anyhow::Result<SocketBindStreamPolicyMap> {
    open_array_map(
        &Path::new(BPF_PIN_DIRECTORY).join("SOCKET_BIND_STREAM_POLICIES"),
        "SOCKET_BIND_STREAM_POLICIES",
    )
}

fn open_array_map<T: aya::Pod>(path: &Path, label: &str) -> anyhow::Result<Array<MapData, T>> {
    let map_data = MapData::from_pin(path)
        .with_context(|| format!("failed to open pinned map '{}'", path.display()))?;
    let map = Map::Array(map_data);
    Array::try_from(map).with_context(|| format!("failed to open {label} as array map"))
}

fn collect_socket_bind_violations(
    static_policies: &mut SocketBindStaticPolicyMap,
    stream_policies: &mut SocketBindStreamPolicyMap,
) -> anyhow::Result<Vec<Violation>> {
    let sockets = read_active_sockets();
    let socket_owners = read_socket_owners();
    let (current_time, current_iso8601_time) = current_utc_time()?;
    let mut violations = Vec::new();

    for socket in sockets {
        if let Some(owners) = socket_owners.get(&socket.inode) {
            for owner in owners {
                collect_socket_violations_for_subject(
                    &socket,
                    owner.uid,
                    owner.pid,
                    owner.command.clone(),
                    static_policies,
                    stream_policies,
                    current_time,
                    current_iso8601_time,
                    &mut violations,
                )?;
            }
        } else {
            collect_socket_violations_for_subject(
                &socket,
                socket.uid,
                0,
                String::from("<unknown>"),
                static_policies,
                stream_policies,
                current_time,
                current_iso8601_time,
                &mut violations,
            )?;
        }
    }

    Ok(violations)
}

fn collect_socket_violations_for_subject(
    socket: &ActiveSocket,
    subject: u32,
    pid: u32,
    command: String,
    static_policies: &mut SocketBindStaticPolicyMap,
    stream_policies: &mut SocketBindStreamPolicyMap,
    current_time: u64,
    current_iso8601_time: Iso8601TimeParts,
    violations: &mut Vec<Violation>,
) -> anyhow::Result<()> {
    let request = SocketBindRequest {
        subject,
        socket_family: socket.family,
        socket_transport: socket.transport,
        socket_port: socket.port,
        socket_ip: socket.ip,
    };

    for index in 0..SOCKET_BIND_STATIC_POLICY_MAX_ENTRIES {
        let policy = static_policies.get(&index, 0).with_context(|| {
            format!("failed to read SOCKET_BIND_STATIC_POLICIES[{index}] for monitor")
        })?;
        if evaluate_socket_bind_static_policy(&request, &policy) == Some(Entitlement::Deny) {
            violations.push(Violation {
                key: ViolationKey {
                    policy_kind: PolicyKind::Static,
                    policy_index: index,
                    pid,
                    socket_inode: socket.inode,
                },
                subject,
                command: command.clone(),
                family: socket.family,
                transport: socket.transport,
                ip: socket.ip,
                port: socket.port,
            });
        }
    }

    for index in 0..SOCKET_BIND_STREAM_POLICY_MAX_ENTRIES {
        let policy = stream_policies.get(&index, 0).with_context(|| {
            format!("failed to read SOCKET_BIND_STREAM_POLICIES[{index}] for monitor")
        })?;
        if evaluate_socket_bind_stream_policy(&request, current_time, current_iso8601_time, &policy)
            == Some(Entitlement::Deny)
        {
            violations.push(Violation {
                key: ViolationKey {
                    policy_kind: PolicyKind::Stream,
                    policy_index: index,
                    pid,
                    socket_inode: socket.inode,
                },
                subject,
                command: command.clone(),
                family: socket.family,
                transport: socket.transport,
                ip: socket.ip,
                port: socket.port,
            });
        }
    }

    Ok(())
}

fn read_active_sockets() -> Vec<ActiveSocket> {
    let mut sockets = Vec::new();
    append_proc_net_sockets(
        "/proc/net/tcp",
        SocketFamily::Inet,
        SocketTransport::Tcp,
        true,
        &mut sockets,
    );
    append_proc_net_sockets(
        "/proc/net/tcp6",
        SocketFamily::Inet6,
        SocketTransport::Tcp,
        true,
        &mut sockets,
    );
    append_proc_net_sockets(
        "/proc/net/udp",
        SocketFamily::Inet,
        SocketTransport::Udp,
        false,
        &mut sockets,
    );
    append_proc_net_sockets(
        "/proc/net/udp6",
        SocketFamily::Inet6,
        SocketTransport::Udp,
        false,
        &mut sockets,
    );
    sockets
}

fn append_proc_net_sockets(
    path: &str,
    family: SocketFamily,
    transport: SocketTransport,
    only_listening: bool,
    sockets: &mut Vec<ActiveSocket>,
) {
    let Ok(content) = fs::read_to_string(path) else {
        return;
    };

    for line in content.lines().skip(1) {
        if let Some(socket) = parse_proc_net_socket_line(line, family, transport, only_listening) {
            sockets.push(socket);
        }
    }
}

fn parse_proc_net_socket_line(
    line: &str,
    family: SocketFamily,
    transport: SocketTransport,
    only_listening: bool,
) -> Option<ActiveSocket> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.len() < 10 {
        return None;
    }

    let state = fields[3];
    if only_listening && state != "0A" {
        return None;
    }

    let (ip, port) = parse_local_socket_address(fields[1], family)?;
    let uid = fields[7].parse().ok()?;
    let inode = fields[9].parse().ok()?;

    Some(ActiveSocket {
        family,
        transport,
        ip,
        port,
        uid,
        inode,
    })
}

fn parse_local_socket_address(
    value: &str,
    family: SocketFamily,
) -> Option<([u8; SOCKET_IP_LEN], u16)> {
    let (address, port) = value.split_once(':')?;
    let mut ip = [0; SOCKET_IP_LEN];

    match family {
        SocketFamily::Inet => {
            ip[..4].copy_from_slice(&parse_proc_net_ipv4(address)?);
        }
        SocketFamily::Inet6 => {
            ip.copy_from_slice(&parse_proc_net_ipv6(address)?);
        }
        SocketFamily::Any => return None,
    }

    Some((ip, u16::from_str_radix(port, 16).ok()?))
}

fn parse_proc_net_ipv4(value: &str) -> Option<[u8; 4]> {
    let raw = u32::from_str_radix(value, 16).ok()?;
    Some(raw.to_le_bytes())
}

fn parse_proc_net_ipv6(value: &str) -> Option<[u8; 16]> {
    if value.len() != 32 {
        return None;
    }

    let mut raw = [0; 16];
    for index in 0..16 {
        raw[index] = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).ok()?;
    }

    let mut ip = [0; 16];
    for index in 0..4 {
        let offset = index * 4;
        ip[offset] = raw[offset + 3];
        ip[offset + 1] = raw[offset + 2];
        ip[offset + 2] = raw[offset + 1];
        ip[offset + 3] = raw[offset];
    }
    Some(ip)
}

fn read_socket_owners() -> HashMap<u64, Vec<ProcessInfo>> {
    let mut owners = HashMap::new();
    let Ok(entries) = fs::read_dir("/proc") else {
        return owners;
    };

    for entry in entries.flatten() {
        let Some(pid) = parse_pid(entry.file_name()) else {
            continue;
        };
        let Some(process) = read_process_info(pid) else {
            continue;
        };
        append_process_socket_owners(pid, process, &mut owners);
    }

    owners
}

fn parse_pid(name: std::ffi::OsString) -> Option<u32> {
    name.to_string_lossy().parse().ok()
}

fn read_process_info(pid: u32) -> Option<ProcessInfo> {
    let status = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let mut command = None;
    let mut uid = None;

    for line in status.lines() {
        if let Some(value) = line.strip_prefix("Name:") {
            command = Some(value.trim().to_string());
        } else if let Some(value) = line.strip_prefix("Uid:") {
            uid = value.split_whitespace().next()?.parse().ok();
        }
    }

    Some(ProcessInfo {
        pid,
        uid: uid?,
        command: command.unwrap_or_else(|| String::from("<unknown>")),
    })
}

fn append_process_socket_owners(
    pid: u32,
    process: ProcessInfo,
    owners: &mut HashMap<u64, Vec<ProcessInfo>>,
) {
    let fd_path = PathBuf::from(format!("/proc/{pid}/fd"));
    let Ok(entries) = fs::read_dir(fd_path) else {
        return;
    };

    for entry in entries.flatten() {
        let Ok(target) = fs::read_link(entry.path()) else {
            continue;
        };
        let Some(inode) = parse_socket_symlink(&target) else {
            continue;
        };
        owners.entry(inode).or_default().push(process.clone());
    }
}

fn parse_socket_symlink(target: &Path) -> Option<u64> {
    let value = target.to_string_lossy();
    let inode = value.strip_prefix("socket:[")?.strip_suffix(']')?;
    inode.parse().ok()
}

fn current_utc_time() -> anyhow::Result<(u64, Iso8601TimeParts)> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system time is before UNIX_EPOCH")?
        .as_secs();
    let time_t = timestamp as libc::c_long;
    let mut tm = MaybeUninit::<libc::tm>::uninit();
    let tm_ptr = unsafe { libc::gmtime_r(&time_t, tm.as_mut_ptr()) };
    if tm_ptr.is_null() {
        return Err(io::Error::last_os_error()).context("gmtime_r failed");
    }
    let tm = unsafe { tm.assume_init() };

    Ok((
        timestamp,
        Iso8601TimeParts::new(
            (tm.tm_year + 1900) as u16,
            (tm.tm_mon + 1) as u8,
            tm.tm_mday as u8,
            tm.tm_hour as u8,
            tm.tm_min as u8,
            tm.tm_sec as u8,
        ),
    ))
}

fn print_violation(violation: &Violation) {
    println!(
        "MONITOR socket_bind violation policy={:?}[{}] uid={} pid={} comm={} family={:?} transport={:?} local={}:{}",
        violation.key.policy_kind,
        violation.key.policy_index,
        violation.subject,
        violation.key.pid,
        violation.command,
        violation.family,
        violation.transport,
        format_ip(violation.family, &violation.ip),
        violation.port,
    );
}

fn enforce_violation(violation: &Violation) {
    let pid = violation.key.pid;
    if pid == 0 {
        eprintln!(
            "MONITOR socket_bind enforcement skipped: unknown pid for socket inode {}",
            violation.key.socket_inode,
        );
        return;
    }

    let current_pid = std::process::id();
    if pid == current_pid {
        eprintln!(
            "MONITOR socket_bind enforcement skipped: refusing to kill monitor process {pid}"
        );
        return;
    }

    let result = unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
    if result == 0 {
        println!(
            "MONITOR socket_bind enforcement signal=SIGTERM pid={} comm={} policy={:?}[{}]",
            pid, violation.command, violation.key.policy_kind, violation.key.policy_index,
        );
    } else {
        eprintln!(
            "MONITOR socket_bind enforcement failed pid={} comm={}: {}",
            pid,
            violation.command,
            io::Error::last_os_error(),
        );
    }
}

fn format_ip(family: SocketFamily, ip: &[u8; SOCKET_IP_LEN]) -> String {
    match family {
        SocketFamily::Inet => Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]).to_string(),
        SocketFamily::Inet6 => Ipv6Addr::from(*ip).to_string(),
        SocketFamily::Any => String::from("<any>"),
    }
}

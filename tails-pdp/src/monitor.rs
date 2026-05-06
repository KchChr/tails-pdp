use std::{
    collections::{HashMap, HashSet},
    ffi::OsString,
    fs, io,
    mem::MaybeUninit,
    net::{Ipv4Addr, Ipv6Addr},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::Context;
use aya::maps::{Array, Map, MapData};
use tails_pdp_common::{
    Entitlement, FILE_OPEN_STATIC_POLICY_MAX_ENTRIES, FILE_OPEN_STREAM_POLICY_MAX_ENTRIES,
    FileOpenRequest, FileOpenStaticPolicy, FileOpenStreamPolicy, Iso8601TimeParts,
    SOCKET_BIND_STATIC_POLICY_MAX_ENTRIES, SOCKET_BIND_STREAM_POLICY_MAX_ENTRIES, SOCKET_IP_LEN,
    SocketBindRequest, SocketBindStaticPolicy, SocketBindStreamPolicy, SocketFamily,
    SocketTransport, command_name, evaluate_file_open_static_policy,
    evaluate_file_open_stream_policy, evaluate_socket_bind_static_policy,
    evaluate_socket_bind_stream_policy,
};
use tokio::time;

use crate::{BPF_PIN_DIRECTORY, fd_revoker::close_remote_fd};

type FileOpenStaticPolicyMap = Array<MapData, FileOpenStaticPolicy>;
type FileOpenStreamPolicyMap = Array<MapData, FileOpenStreamPolicy>;
type SocketBindStaticPolicyMap = Array<MapData, SocketBindStaticPolicy>;
type SocketBindStreamPolicyMap = Array<MapData, SocketBindStreamPolicy>;

#[derive(Clone, Debug)]
struct ActiveSocket {
    family: SocketFamily,
    transport: SocketTransport,
    ip: [u8; SOCKET_IP_LEN],
    port: u16,
    inode: u64,
}

#[derive(Clone, Debug)]
struct ProcessInfo {
    pid: u32,
    uid: u32,
    command: String,
}

#[derive(Clone, Debug)]
struct ProcessFd {
    process: ProcessInfo,
    fd: i32,
    target: FdTarget,
}

#[derive(Clone, Debug)]
enum FdTarget {
    File { device: u64, inode: u64 },
    Socket { socket: ActiveSocket },
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct ViolationKey {
    policy_kind: PolicyKind,
    policy_index: u32,
    resource_kind: ResourceKind,
    pid: u32,
    fd: i32,
}

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
enum PolicyKind {
    Static,
    Stream,
}

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
enum ResourceKind {
    File,
    Socket,
}

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
struct RevocationKey {
    pid: u32,
    fd: i32,
}

struct Violation {
    key: ViolationKey,
    subject: u32,
    command: String,
    resource: ViolationResource,
}

enum ViolationResource {
    File {
        device: u64,
        inode: u64,
    },
    Socket {
        family: SocketFamily,
        transport: SocketTransport,
        ip: [u8; SOCKET_IP_LEN],
        port: u16,
        inode: u64,
    },
}

struct PolicyMaps {
    file_open_static: FileOpenStaticPolicyMap,
    file_open_stream: FileOpenStreamPolicyMap,
    socket_bind_static: SocketBindStaticPolicyMap,
    socket_bind_stream: SocketBindStreamPolicyMap,
}

pub async fn run_policy_monitor() -> anyhow::Result<()> {
    let mut policies = open_policy_maps()?;
    let mut previous_violations = HashSet::new();
    let mut interval = time::interval(Duration::from_secs(1));

    loop {
        interval.tick().await;

        match collect_policy_violations(&mut policies) {
            Ok(current_violations) => {
                let mut current_keys = HashSet::new();
                let mut revoked_in_scan = HashSet::new();

                for violation in current_violations {
                    let first_seen_in_scan = current_keys.insert(violation.key.clone());
                    if !first_seen_in_scan {
                        continue;
                    }

                    if !previous_violations.contains(&violation.key) {
                        print_violation(&violation);
                    }

                    enforce_violation(&violation, &mut revoked_in_scan);
                }

                previous_violations = current_keys;
            }
            Err(error) => {
                eprintln!("MONITOR scan failed: {error:#}");
            }
        }
    }
}

fn open_policy_maps() -> anyhow::Result<PolicyMaps> {
    Ok(PolicyMaps {
        file_open_static: open_array_map(
            &Path::new(BPF_PIN_DIRECTORY).join("FILE_OPEN_STATIC_POLICIES"),
            "FILE_OPEN_STATIC_POLICIES",
        )?,
        file_open_stream: open_array_map(
            &Path::new(BPF_PIN_DIRECTORY).join("FILE_OPEN_STREAM_POLICIES"),
            "FILE_OPEN_STREAM_POLICIES",
        )?,
        socket_bind_static: open_array_map(
            &Path::new(BPF_PIN_DIRECTORY).join("SOCKET_BIND_STATIC_POLICIES"),
            "SOCKET_BIND_STATIC_POLICIES",
        )?,
        socket_bind_stream: open_array_map(
            &Path::new(BPF_PIN_DIRECTORY).join("SOCKET_BIND_STREAM_POLICIES"),
            "SOCKET_BIND_STREAM_POLICIES",
        )?,
    })
}

fn open_array_map<T: aya::Pod>(path: &Path, label: &str) -> anyhow::Result<Array<MapData, T>> {
    let map_data = MapData::from_pin(path)
        .with_context(|| format!("failed to open pinned map '{}'", path.display()))?;
    let map = Map::Array(map_data);
    Array::try_from(map).with_context(|| format!("failed to open {label} as array map"))
}

fn collect_policy_violations(policies: &mut PolicyMaps) -> anyhow::Result<Vec<Violation>> {
    let socket_index = read_active_sockets()
        .into_iter()
        .map(|socket| (socket.inode, socket))
        .collect();
    let process_fds = read_process_fds(&socket_index);
    let (current_time, current_iso8601_time) = current_utc_time()?;
    let mut violations = Vec::new();

    for process_fd in process_fds {
        match &process_fd.target {
            FdTarget::File { device, inode } => collect_file_open_violations(
                &process_fd,
                *device,
                *inode,
                policies,
                current_time,
                current_iso8601_time,
                &mut violations,
            )?,
            FdTarget::Socket { socket } => collect_socket_bind_violations(
                &process_fd,
                socket,
                policies,
                current_time,
                current_iso8601_time,
                &mut violations,
            )?,
        }
    }

    Ok(violations)
}

fn collect_file_open_violations(
    process_fd: &ProcessFd,
    device: u64,
    inode: u64,
    policies: &mut PolicyMaps,
    current_time: u64,
    current_iso8601_time: Iso8601TimeParts,
    violations: &mut Vec<Violation>,
) -> anyhow::Result<()> {
    let request = FileOpenRequest {
        subject: process_fd.process.uid,
        command: command_name(&process_fd.process.command),
        resource_device: device,
        resource_inode: inode,
    };

    for index in 0..FILE_OPEN_STATIC_POLICY_MAX_ENTRIES {
        let policy = policies.file_open_static.get(&index, 0).with_context(|| {
            format!("failed to read FILE_OPEN_STATIC_POLICIES[{index}] for monitor")
        })?;
        if evaluate_file_open_static_policy(&request, &policy) == Some(Entitlement::Deny) {
            violations.push(file_violation(
                process_fd,
                PolicyKind::Static,
                index,
                device,
                inode,
            ));
        }
    }

    for index in 0..FILE_OPEN_STREAM_POLICY_MAX_ENTRIES {
        let policy = policies.file_open_stream.get(&index, 0).with_context(|| {
            format!("failed to read FILE_OPEN_STREAM_POLICIES[{index}] for monitor")
        })?;
        if evaluate_file_open_stream_policy(&request, current_time, current_iso8601_time, &policy)
            == Some(Entitlement::Deny)
        {
            violations.push(file_violation(
                process_fd,
                PolicyKind::Stream,
                index,
                device,
                inode,
            ));
        }
    }

    Ok(())
}

fn collect_socket_bind_violations(
    process_fd: &ProcessFd,
    socket: &ActiveSocket,
    policies: &mut PolicyMaps,
    current_time: u64,
    current_iso8601_time: Iso8601TimeParts,
    violations: &mut Vec<Violation>,
) -> anyhow::Result<()> {
    let request = SocketBindRequest {
        subject: process_fd.process.uid,
        socket_family: socket.family,
        socket_transport: socket.transport,
        socket_port: socket.port,
        socket_ip: socket.ip,
    };

    for index in 0..SOCKET_BIND_STATIC_POLICY_MAX_ENTRIES {
        let policy = policies
            .socket_bind_static
            .get(&index, 0)
            .with_context(|| {
                format!("failed to read SOCKET_BIND_STATIC_POLICIES[{index}] for monitor")
            })?;
        if evaluate_socket_bind_static_policy(&request, &policy) == Some(Entitlement::Deny) {
            violations.push(socket_violation(
                process_fd,
                PolicyKind::Static,
                index,
                socket,
            ));
        }
    }

    for index in 0..SOCKET_BIND_STREAM_POLICY_MAX_ENTRIES {
        let policy = policies
            .socket_bind_stream
            .get(&index, 0)
            .with_context(|| {
                format!("failed to read SOCKET_BIND_STREAM_POLICIES[{index}] for monitor")
            })?;
        if evaluate_socket_bind_stream_policy(&request, current_time, current_iso8601_time, &policy)
            == Some(Entitlement::Deny)
        {
            violations.push(socket_violation(
                process_fd,
                PolicyKind::Stream,
                index,
                socket,
            ));
        }
    }

    Ok(())
}

fn file_violation(
    process_fd: &ProcessFd,
    policy_kind: PolicyKind,
    policy_index: u32,
    device: u64,
    inode: u64,
) -> Violation {
    Violation {
        key: ViolationKey {
            policy_kind,
            policy_index,
            resource_kind: ResourceKind::File,
            pid: process_fd.process.pid,
            fd: process_fd.fd,
        },
        subject: process_fd.process.uid,
        command: process_fd.process.command.clone(),
        resource: ViolationResource::File { device, inode },
    }
}

fn socket_violation(
    process_fd: &ProcessFd,
    policy_kind: PolicyKind,
    policy_index: u32,
    socket: &ActiveSocket,
) -> Violation {
    Violation {
        key: ViolationKey {
            policy_kind,
            policy_index,
            resource_kind: ResourceKind::Socket,
            pid: process_fd.process.pid,
            fd: process_fd.fd,
        },
        subject: process_fd.process.uid,
        command: process_fd.process.command.clone(),
        resource: ViolationResource::Socket {
            family: socket.family,
            transport: socket.transport,
            ip: socket.ip,
            port: socket.port,
            inode: socket.inode,
        },
    }
}

fn enforce_violation(violation: &Violation, revoked_in_scan: &mut HashSet<RevocationKey>) {
    let key = RevocationKey {
        pid: violation.key.pid,
        fd: violation.key.fd,
    };
    if !revoked_in_scan.insert(key) {
        return;
    }
    if should_skip_enforcement(violation.key.pid) {
        return;
    }

    match close_remote_fd(violation.key.pid, violation.key.fd) {
        Ok(()) => {
            println!(
                "MONITOR closed pid={} fd={} for {:?} policy {:?}[{}]",
                violation.key.pid,
                violation.key.fd,
                violation.key.resource_kind,
                violation.key.policy_kind,
                violation.key.policy_index,
            );
        }
        Err(error) => {
            eprintln!(
                "MONITOR failed to close pid={} fd={} for {:?} policy {:?}[{}]: {error:#}",
                violation.key.pid,
                violation.key.fd,
                violation.key.resource_kind,
                violation.key.policy_kind,
                violation.key.policy_index,
            );
        }
    }
}

fn should_skip_enforcement(pid: u32) -> bool {
    pid == 0 || pid == 1 || pid == std::process::id()
}

fn read_process_fds(socket_index: &HashMap<u64, ActiveSocket>) -> Vec<ProcessFd> {
    let mut process_fds = Vec::new();
    let Ok(entries) = fs::read_dir("/proc") else {
        return process_fds;
    };

    for entry in entries.flatten() {
        let Some(pid) = parse_pid(entry.file_name()) else {
            continue;
        };
        let Some(process) = read_process_info(pid) else {
            continue;
        };
        append_process_fds(process, socket_index, &mut process_fds);
    }

    process_fds
}

fn append_process_fds(
    process: ProcessInfo,
    socket_index: &HashMap<u64, ActiveSocket>,
    process_fds: &mut Vec<ProcessFd>,
) {
    let fd_path = PathBuf::from(format!("/proc/{}/fd", process.pid));
    let Ok(entries) = fs::read_dir(fd_path) else {
        return;
    };

    for entry in entries.flatten() {
        let Some(fd) = parse_fd(entry.file_name()) else {
            continue;
        };
        let Some(target) = read_fd_target(&entry.path(), socket_index) else {
            continue;
        };
        process_fds.push(ProcessFd {
            process: process.clone(),
            fd,
            target,
        });
    }
}

fn read_fd_target(path: &Path, socket_index: &HashMap<u64, ActiveSocket>) -> Option<FdTarget> {
    let target = fs::read_link(path).ok()?;
    if let Some(inode) = parse_socket_symlink(&target) {
        return socket_index
            .get(&inode)
            .cloned()
            .map(|socket| FdTarget::Socket { socket });
    }

    let metadata = fs::metadata(path).ok()?;
    if !metadata.file_type().is_file() {
        return None;
    }

    Some(FdTarget::File {
        device: encode_kernel_dev_t(metadata.dev()),
        inode: metadata.ino(),
    })
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
    let inode = fields[9].parse().ok()?;

    Some(ActiveSocket {
        family,
        transport,
        ip,
        port,
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

fn parse_pid(name: OsString) -> Option<u32> {
    name.to_string_lossy().parse().ok()
}

fn parse_fd(name: OsString) -> Option<i32> {
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

fn parse_socket_symlink(target: &Path) -> Option<u64> {
    let value = target.to_string_lossy();
    let inode = value.strip_prefix("socket:[")?.strip_suffix(']')?;
    inode.parse().ok()
}

fn encode_kernel_dev_t(device: u64) -> u64 {
    let major = libc::major(device) as u64;
    let minor = libc::minor(device) as u64;
    (major << 20) | minor
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
    match &violation.resource {
        ViolationResource::File { device, inode } => {
            println!(
                "MONITOR file_open violation policy={:?}[{}] uid={} pid={} fd={} comm={} dev={} ino={}",
                violation.key.policy_kind,
                violation.key.policy_index,
                violation.subject,
                violation.key.pid,
                violation.key.fd,
                violation.command,
                device,
                inode,
            );
        }
        ViolationResource::Socket {
            family,
            transport,
            ip,
            port,
            inode,
        } => {
            println!(
                "MONITOR socket_bind violation policy={:?}[{}] uid={} pid={} fd={} comm={} family={:?} transport={:?} local={}:{} socket_inode={}",
                violation.key.policy_kind,
                violation.key.policy_index,
                violation.subject,
                violation.key.pid,
                violation.key.fd,
                violation.command,
                family,
                transport,
                format_ip(*family, ip),
                port,
                inode,
            );
        }
    }
}

fn format_ip(family: SocketFamily, ip: &[u8; SOCKET_IP_LEN]) -> String {
    match family {
        SocketFamily::Inet => Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]).to_string(),
        SocketFamily::Inet6 => Ipv6Addr::from(*ip).to_string(),
        SocketFamily::Any => String::from("<any>"),
    }
}

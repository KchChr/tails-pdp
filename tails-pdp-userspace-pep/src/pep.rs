use std::{
    collections::HashSet,
    ffi::OsString,
    fs,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::Context;
use aya::maps::{Array, HashMap as AyaHashMap, MapData};
use log::{info, warn};
use tails_pdp_common::{
    AttributeKey, AttributeValue, Entitlement, FileOpenRequest, FileOpenStaticPolicy,
    FileOpenStreamPolicy, MAX_ATTRIBUTE_CONDITIONS, POLICY_BANK_SIZE, PolicyTime, attribute_bank,
    attribute_object_ids, command_name, evaluate_file_open_static_policy,
    file_open_stream_legacy_entitlement, file_open_stream_policy_applies_to_request,
    matches_attribute_condition, policy_bank_offset,
};
use tails_pdp_userspace_common::{EnforcementTrigger, open_pinned_array, open_pinned_hash_map};
use tokio::{sync::mpsc, time};

use crate::fd_revoker::close_remote_fd;

type FileOpenStaticPolicyMap = Array<MapData, FileOpenStaticPolicy>;
type FileOpenStreamPolicyMap = Array<MapData, FileOpenStreamPolicy>;
type PolicyGenerationMap = Array<MapData, u32>;
type CurrentTimeMap = Array<MapData, u64>;
type AttributeGenerationMap = Array<MapData, u32>;
type AttributeMap = AyaHashMap<MapData, AttributeKey, AttributeValue>;

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
    device: u64,
    inode: u64,
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
}

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
struct FdKey {
    pid: u32,
    fd: i32,
}

struct Violation {
    key: ViolationKey,
}

trait FdCloser {
    fn close(&mut self, pid: u32, fd: i32) -> anyhow::Result<()>;
}

struct PtraceFdCloser;

impl FdCloser for PtraceFdCloser {
    fn close(&mut self, pid: u32, fd: i32) -> anyhow::Result<()> {
        close_remote_fd(pid, fd)
    }
}

struct PolicyMaps {
    policy_generation: PolicyGenerationMap,
    file_open_static: FileOpenStaticPolicyMap,
    file_open_stream: FileOpenStreamPolicyMap,
    attribute_generation: AttributeGenerationMap,
    attributes: AttributeMap,
    current_time: CurrentTimeMap,
}

/// Immutable inputs shared by every file-descriptor evaluation in one `/proc` scan.
struct ScanContext {
    policy_generation: u32,
    attribute_generation: u32,
    current_time: PolicyTime,
    current_attribute_bank: u32,
    policy_bank_offset: u32,
}

pub async fn run_userspace_pep(
    mut enforcement_triggers: mpsc::Receiver<EnforcementTrigger>,
) -> anyhow::Result<()> {
    let mut policies = open_policy_maps()?;
    let mut fd_closer = PtraceFdCloser;

    loop {
        let next_time_boundary = next_time_boundary(&mut policies)?;
        if let Some(unix_seconds) = next_time_boundary {
            info!(
                "USERSPACE_PEP scheduled time-condition re-evaluation at unix_seconds={}",
                unix_seconds
            );
        }
        let trigger = wait_for_trigger(&mut enforcement_triggers, next_time_boundary).await?;

        let mut triggers = vec![trigger];
        while let Ok(trigger) = enforcement_triggers.try_recv() {
            triggers.push(trigger);
        }
        if triggers.len() > 1 {
            info!(
                "USERSPACE_PEP coalesced {} activation events into one scan",
                triggers.len()
            );
        }

        run_scan(&mut policies, &mut fd_closer, &triggers);
    }
}

async fn wait_for_trigger(
    enforcement_triggers: &mut mpsc::Receiver<EnforcementTrigger>,
    next_time_boundary: Option<u64>,
) -> anyhow::Result<EnforcementTrigger> {
    match next_time_boundary {
        Some(unix_seconds) => {
            let delay = Duration::from_secs(unix_seconds.saturating_sub(current_unix_timestamp()?));
            let trigger = tokio::select! {
                trigger = enforcement_triggers.recv() => trigger.ok_or_else(|| anyhow::anyhow!("userspace PEP trigger channel closed")),
                _ = time::sleep(delay) => Ok(EnforcementTrigger::TimeConditionChanged { unix_seconds }),
            }?;
            if matches!(trigger, EnforcementTrigger::TimeConditionChanged { .. }) {
                info!(
                    "USERSPACE_PEP reached scheduled time-condition boundary unix_seconds={unix_seconds}"
                );
            }
            Ok(trigger)
        }
        None => enforcement_triggers
            .recv()
            .await
            .ok_or_else(|| anyhow::anyhow!("userspace PEP trigger channel closed")),
    }
}

fn run_scan<C: FdCloser>(
    policies: &mut PolicyMaps,
    fd_closer: &mut C,
    triggers: &[EnforcementTrigger],
) {
    if triggers
        .iter()
        .any(|trigger| matches!(trigger, EnforcementTrigger::TimeConditionChanged { .. }))
    {
        match current_unix_timestamp().and_then(|unix_seconds| {
            policies
                .current_time
                .set(0, unix_seconds, 0)
                .context("failed to refresh CURRENT_TIME[0] at time-condition boundary")
        }) {
            Ok(()) => {}
            Err(error) => {
                warn!("USERSPACE_PEP time-triggered scan skipped: {error:#}");
                return;
            }
        }
    }
    let trigger_summary = triggers
        .iter()
        .map(trigger_label)
        .collect::<Vec<_>>()
        .join(", ");
    match read_scan_context(policies) {
        Ok(scan) => {
            info!(
                "USERSPACE_PEP scan started cause=[{}] policy_generation={} attribute_generation={}",
                trigger_summary, scan.policy_generation, scan.attribute_generation
            );
            let current_violations = match collect_policy_violations(policies, &scan) {
                Ok(violations) => violations,
                Err(error) => {
                    warn!("USERSPACE_PEP scan failed cause=[{trigger_summary}]: {error:#}");
                    return;
                }
            };
            let mut current_keys = HashSet::new();
            let mut revoked_in_scan = HashSet::new();
            let mut violations = 0;

            for violation in current_violations {
                if !current_keys.insert(violation.key.clone()) {
                    continue;
                }
                violations += 1;
                enforce_violation(&violation, &mut revoked_in_scan, fd_closer);
            }
            info!(
                "USERSPACE_PEP scan completed policy_generation={} attribute_generation={} violations={} revocation_attempts={}",
                scan.policy_generation,
                scan.attribute_generation,
                violations,
                revoked_in_scan.len()
            );
        }
        Err(error) => warn!("USERSPACE_PEP scan failed cause=[{trigger_summary}]: {error:#}"),
    }
}

fn trigger_label(trigger: &EnforcementTrigger) -> String {
    match trigger {
        EnforcementTrigger::PolicyGenerationActivated { generation } => {
            format!("policy:{generation}")
        }
        EnforcementTrigger::AttributeGenerationActivated { generation } => {
            format!("attributes:{generation}")
        }
        EnforcementTrigger::TimeConditionChanged { unix_seconds } => format!("time:{unix_seconds}"),
    }
}

fn current_unix_timestamp() -> anyhow::Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before UNIX_EPOCH")?
        .as_secs())
}

fn open_policy_maps() -> anyhow::Result<PolicyMaps> {
    Ok(PolicyMaps {
        policy_generation: open_pinned_array("POLICY_GENERATION")?,
        file_open_static: open_pinned_array("FILE_OPEN_STATIC_POLICIES")?,
        file_open_stream: open_pinned_array("FILE_OPEN_STREAM_POLICIES")?,
        attribute_generation: open_pinned_array("ATTRIBUTE_GENERATION")?,
        attributes: open_pinned_hash_map("ATTRIBUTES")?,
        current_time: open_pinned_array("CURRENT_TIME")?,
    })
}

fn read_scan_context(policies: &mut PolicyMaps) -> anyhow::Result<ScanContext> {
    let generation = policies
        .policy_generation
        .get(&0, 0)
        .context("failed to read POLICY_GENERATION[0] for userspace PEP")?;
    let bank_offset = policy_bank_offset(generation);
    let current_unix_time = policies
        .current_time
        .get(&0, 0)
        .context("failed to read CURRENT_TIME[0] for userspace PEP")?;
    let current_time = PolicyTime::from_unix_seconds(current_unix_time);
    let attribute_generation = policies
        .attribute_generation
        .get(&0, 0)
        .context("failed to read ATTRIBUTE_GENERATION[0] for userspace PEP")?;
    let current_attribute_bank = attribute_bank(attribute_generation);
    Ok(ScanContext {
        policy_generation: generation,
        attribute_generation,
        current_time,
        current_attribute_bank,
        policy_bank_offset: bank_offset,
    })
}

fn collect_policy_violations(
    policies: &mut PolicyMaps,
    scan: &ScanContext,
) -> anyhow::Result<Vec<Violation>> {
    let process_fds = read_process_fds();
    let mut violations = Vec::new();

    for process_fd in process_fds {
        collect_file_open_violations(
            &process_fd,
            process_fd.device,
            process_fd.inode,
            policies,
            scan,
            &mut violations,
        )?;
    }

    Ok(violations)
}

/// Returns the earliest future Unix second where one active time condition can change truth value.
/// Attribute-only policies do not require a timer and are re-evaluated on attribute activation.
fn next_time_boundary(policies: &mut PolicyMaps) -> anyhow::Result<Option<u64>> {
    let generation = policies
        .policy_generation
        .get(&0, 0)
        .context("failed to read POLICY_GENERATION[0] for time scheduling")?;
    let bank_offset = policy_bank_offset(generation);
    let now = current_unix_timestamp()?;
    let mut next = None;

    for index in 0..POLICY_BANK_SIZE {
        let map_index = bank_offset + index;
        let policy = policies
            .file_open_stream
            .get(&map_index, 0)
            .with_context(|| {
                format!("failed to read FILE_OPEN_STREAM_POLICIES[{map_index}] for time scheduling")
            })?;
        if policy.enabled == 0
            || policy.action != tails_pdp_common::PolicyAction::FileOpen
            || policy.stream_condition_enabled == 0
        {
            continue;
        }
        if let Some(boundary) = next_policy_time_boundary(now, &policy) {
            next = Some(next.map_or(boundary, |current: u64| current.min(boundary)));
        }
    }
    Ok(next)
}

fn next_policy_time_boundary(now: u64, policy: &FileOpenStreamPolicy) -> Option<u64> {
    match policy.attribute {
        tails_pdp_common::StreamAttribute::Time => next_modulo_boundary(now, policy),
        tails_pdp_common::StreamAttribute::Hour => next_component_boundary(now, policy, 3_600, 24),
        tails_pdp_common::StreamAttribute::Minute => next_component_boundary(now, policy, 60, 60),
        tails_pdp_common::StreamAttribute::Second => next_component_boundary(now, policy, 1, 60),
    }
}

fn next_component_boundary(
    now: u64,
    policy: &FileOpenStreamPolicy,
    seconds_per_step: u64,
    cycle_len: u64,
) -> Option<u64> {
    let current = time_condition_matches(now, policy);
    let mut candidate = (now / seconds_per_step + 1) * seconds_per_step;
    for _ in 0..cycle_len {
        if time_condition_matches(candidate, policy) != current {
            return Some(candidate);
        }
        candidate += seconds_per_step;
    }
    None
}

fn next_modulo_boundary(now: u64, policy: &FileOpenStreamPolicy) -> Option<u64> {
    let modulo = policy.modulo;
    if modulo == 0 {
        return None;
    }
    let value = policy.value;
    let residues: &[u64] = match policy.operator {
        tails_pdp_common::StreamOperator::LessThan if value > 0 && value < modulo => &[value, 0],
        tails_pdp_common::StreamOperator::LessThanOrEqual if value < modulo - 1 => &[value + 1, 0],
        tails_pdp_common::StreamOperator::Equal if value < modulo && modulo > 1 => {
            &[value, (value + 1) % modulo]
        }
        tails_pdp_common::StreamOperator::GreaterThanOrEqual if value > 0 && value < modulo => {
            &[value, 0]
        }
        tails_pdp_common::StreamOperator::GreaterThan if value < modulo - 1 => &[value + 1, 0],
        _ => return None,
    };
    residues
        .iter()
        .map(|residue| next_residue_after(now, modulo, *residue))
        .min()
}

fn next_residue_after(now: u64, modulo: u64, residue: u64) -> u64 {
    let current = now % modulo;
    let delta = if residue > current {
        residue - current
    } else {
        modulo - current + residue
    };
    now.saturating_add(delta)
}

fn time_condition_matches(unix_seconds: u64, policy: &FileOpenStreamPolicy) -> bool {
    let time = PolicyTime::from_unix_seconds(unix_seconds);
    let value = match policy.attribute {
        tails_pdp_common::StreamAttribute::Time => {
            if policy.modulo == 0 {
                return false;
            }
            unix_seconds % policy.modulo
        }
        tails_pdp_common::StreamAttribute::Hour => time.hour as u64,
        tails_pdp_common::StreamAttribute::Minute => time.minute as u64,
        tails_pdp_common::StreamAttribute::Second => time.second as u64,
    };
    tails_pdp_common::matches_stream_operator(policy.operator, value, policy.value)
}

fn collect_file_open_violations(
    process_fd: &ProcessFd,
    device: u64,
    inode: u64,
    policies: &mut PolicyMaps,
    scan: &ScanContext,
    violations: &mut Vec<Violation>,
) -> anyhow::Result<()> {
    let request = FileOpenRequest {
        subject: process_fd.process.uid,
        command: command_name(&process_fd.process.command),
        resource_device: device,
        resource_inode: inode,
    };

    for index in 0..POLICY_BANK_SIZE {
        let map_index = scan.policy_bank_offset + index;
        let policy = policies
            .file_open_static
            .get(&map_index, 0)
            .with_context(|| {
                format!("failed to read FILE_OPEN_STATIC_POLICIES[{map_index}] for userspace PEP")
            })?;
        if evaluate_file_open_static_policy(&request, &policy) == Some(Entitlement::Deny) {
            violations.push(file_violation(process_fd, PolicyKind::Static, index));
        }
    }

    for index in 0..POLICY_BANK_SIZE {
        let map_index = scan.policy_bank_offset + index;
        let policy = policies
            .file_open_stream
            .get(&map_index, 0)
            .with_context(|| {
                format!("failed to read FILE_OPEN_STREAM_POLICIES[{map_index}] for userspace PEP")
            })?;
        if file_open_stream_policy_applies_to_request(&request, &policy)
            && attribute_conditions_match(
                policy.attribute_condition_count,
                &policy.attribute_conditions,
                request.subject,
                request.resource_device,
                request.resource_inode,
                scan.current_attribute_bank,
                &policies.attributes,
            )
            && file_open_stream_legacy_entitlement(scan.current_time, &policy)
                == Some(Entitlement::Deny)
        {
            violations.push(file_violation(process_fd, PolicyKind::Stream, index));
        }
    }

    Ok(())
}

fn attribute_conditions_match(
    condition_count: u8,
    conditions: &[tails_pdp_common::AttributeCondition; MAX_ATTRIBUTE_CONDITIONS],
    subject: u32,
    resource_device: u64,
    resource_inode: u64,
    bank: u32,
    attributes: &AttributeMap,
) -> bool {
    for condition in conditions
        .iter()
        .take((condition_count as usize).min(MAX_ATTRIBUTE_CONDITIONS))
    {
        let (object_id_primary, object_id_secondary) = attribute_object_ids(
            condition.namespace,
            subject,
            resource_device,
            resource_inode,
        );
        let key = AttributeKey::new(
            bank,
            condition.namespace,
            object_id_primary,
            object_id_secondary,
            condition.name_hash,
        );
        let Ok(value) = attributes.get(&key, 0) else {
            return false;
        };
        if !matches_attribute_condition(condition, &value) {
            return false;
        }
    }
    true
}

fn file_violation(process_fd: &ProcessFd, policy_kind: PolicyKind, policy_index: u32) -> Violation {
    Violation {
        key: ViolationKey {
            policy_kind,
            policy_index,
            resource_kind: ResourceKind::File,
            pid: process_fd.process.pid,
            fd: process_fd.fd,
        },
    }
}

fn enforce_violation<C: FdCloser>(
    violation: &Violation,
    revoked_in_scan: &mut HashSet<FdKey>,
    fd_closer: &mut C,
) {
    let key = FdKey {
        pid: violation.key.pid,
        fd: violation.key.fd,
    };
    if !revoked_in_scan.insert(key) {
        return;
    }
    match fd_closer.close(violation.key.pid, violation.key.fd) {
        Ok(()) => {
            info!(
                "USERSPACE_PEP closed pid={} fd={} for {:?} policy {:?}[{}]",
                violation.key.pid,
                violation.key.fd,
                violation.key.resource_kind,
                violation.key.policy_kind,
                violation.key.policy_index,
            );
        }
        Err(error) => {
            warn!(
                "USERSPACE_PEP failed to close pid={} fd={} for {:?} policy {:?}[{}]: {error:#}",
                violation.key.pid,
                violation.key.fd,
                violation.key.resource_kind,
                violation.key.policy_kind,
                violation.key.policy_index,
            );
        }
    }
}

fn read_process_fds() -> Vec<ProcessFd> {
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
        append_process_fds(process, &mut process_fds);
    }

    process_fds
}

fn append_process_fds(process: ProcessInfo, process_fds: &mut Vec<ProcessFd>) {
    let fd_path = PathBuf::from(format!("/proc/{}/fd", process.pid));
    let Ok(entries) = fs::read_dir(fd_path) else {
        return;
    };

    for entry in entries.flatten() {
        let Some(fd) = parse_fd(entry.file_name()) else {
            continue;
        };
        let Some((device, inode)) = read_file_identity(&entry.path()) else {
            continue;
        };
        process_fds.push(ProcessFd {
            process: process.clone(),
            fd,
            device,
            inode,
        });
    }
}

fn read_file_identity(path: &Path) -> Option<(u64, u64)> {
    let metadata = fs::metadata(path).ok()?;
    if !metadata.file_type().is_file() {
        return None;
    }

    Some((encode_kernel_dev_t(metadata.dev()), metadata.ino()))
}

fn parse_pid(name: OsString) -> Option<u32> {
    name.to_string_lossy().parse().ok()
}

fn parse_fd(name: OsString) -> Option<i32> {
    name.to_string_lossy().parse().ok()
}

fn read_process_info(pid: u32) -> Option<ProcessInfo> {
    let status = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    parse_process_info(pid, &status)
}

fn parse_process_info(pid: u32, status: &str) -> Option<ProcessInfo> {
    let mut command = None;
    let mut uid = None;

    for line in status.lines() {
        if let Some(value) = line.strip_prefix("Name:") {
            command = Some(value.trim().to_string());
        } else if let Some(value) = line.strip_prefix("Uid:") {
            // proc_pid_status(5) lists real, effective, saved-set and filesystem UID.
            // Policies deliberately use the real UID, matching the eBPF context UID.
            uid = value.split_whitespace().next()?.parse().ok();
        }
    }

    Some(ProcessInfo {
        pid,
        uid: uid?,
        command: command.unwrap_or_else(|| String::from("<unknown>")),
    })
}

fn encode_kernel_dev_t(device: u64) -> u64 {
    let major = libc::major(device) as u64;
    let minor = libc::minor(device) as u64;
    (major << 20) | minor
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    #[derive(Default)]
    struct FakeFdCloser {
        calls: Vec<(u32, i32)>,
        fail: bool,
    }

    impl FdCloser for FakeFdCloser {
        fn close(&mut self, pid: u32, fd: i32) -> anyhow::Result<()> {
            self.calls.push((pid, fd));
            if self.fail {
                anyhow::bail!("injected close failure");
            }
            Ok(())
        }
    }

    fn process_fd(pid: u32, fd: i32) -> ProcessFd {
        ProcessFd {
            process: ProcessInfo {
                pid,
                uid: 1000,
                command: String::from("test-process"),
            },
            fd,
            device: 42,
            inode: 99,
        }
    }

    #[test]
    fn parses_only_numeric_process_and_fd_names() {
        assert_eq!(parse_pid(OsString::from("1234")), Some(1234));
        assert_eq!(parse_pid(OsString::from("self")), None);
        assert_eq!(parse_fd(OsString::from("17")), Some(17));
        assert_eq!(parse_fd(OsString::from("cwd")), None);
    }

    #[test]
    fn process_subject_uses_real_uid_from_proc_status() {
        let status = "Name:\tcredential-test\nUid:\t1000\t0\t2000\t3000\n";

        let process = parse_process_info(4242, status).expect("valid process status");

        assert_eq!(process.pid, 4242);
        assert_eq!(process.uid, 1000);
        assert_eq!(process.command, "credential-test");
    }

    #[test]
    fn regular_files_are_identified_but_directories_are_ignored() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "tails-pdp-userspace-pep-test-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&directory).expect("create test directory");
        let file = directory.join("resource");
        fs::write(&file, b"test").expect("create test file");

        assert!(read_file_identity(&file).is_some());
        assert_eq!(read_file_identity(&directory), None);

        fs::remove_dir_all(directory).expect("remove test directory");
    }

    #[test]
    fn violation_targets_exactly_the_matching_file_descriptor() {
        let process_fd = process_fd(4242, 17);
        let violation = file_violation(&process_fd, PolicyKind::Stream, 3);

        assert_eq!(violation.key.pid, 4242);
        assert_eq!(violation.key.fd, 17);
    }

    #[test]
    fn same_file_descriptor_is_closed_only_once_per_scan() {
        let process_fd = process_fd(4242, 17);
        let static_violation = file_violation(&process_fd, PolicyKind::Static, 0);
        let stream_violation = file_violation(&process_fd, PolicyKind::Stream, 1);
        let mut revoked = HashSet::new();
        let mut closer = FakeFdCloser::default();

        enforce_violation(&static_violation, &mut revoked, &mut closer);
        enforce_violation(&stream_violation, &mut revoked, &mut closer);

        assert_eq!(closer.calls, [(4242, 17)]);
    }

    #[test]
    fn other_file_descriptors_remain_independently_enforceable() {
        let first = file_violation(&process_fd(4242, 17), PolicyKind::Static, 0);
        let second = file_violation(&process_fd(4242, 18), PolicyKind::Static, 0);
        let mut revoked = HashSet::new();
        let mut closer = FakeFdCloser::default();

        enforce_violation(&first, &mut revoked, &mut closer);
        enforce_violation(&second, &mut revoked, &mut closer);

        assert_eq!(closer.calls, [(4242, 17), (4242, 18)]);
    }

    #[test]
    fn failed_close_is_attempted_once_without_aborting_scan() {
        let violation = file_violation(&process_fd(4242, 17), PolicyKind::Static, 0);
        let mut revoked = HashSet::new();
        let mut closer = FakeFdCloser {
            fail: true,
            ..FakeFdCloser::default()
        };

        enforce_violation(&violation, &mut revoked, &mut closer);
        enforce_violation(&violation, &mut revoked, &mut closer);

        assert_eq!(closer.calls, [(4242, 17)]);
    }

    #[test]
    fn schedules_hour_policy_at_the_next_decision_change() {
        let mut policy = FileOpenStreamPolicy::time(
            Entitlement::Deny,
            1000,
            "",
            "",
            tails_pdp_common::StreamOperator::GreaterThanOrEqual,
            1,
            16,
        );
        policy.attribute = tails_pdp_common::StreamAttribute::Hour;
        policy.modulo = 0;

        let now = 15 * 3_600 + 42;
        assert_eq!(next_policy_time_boundary(now, &policy), Some(16 * 3_600));
    }

    #[test]
    fn schedules_modulo_policy_at_the_next_truth_value_change() {
        let policy = FileOpenStreamPolicy::time(
            Entitlement::Deny,
            1000,
            "",
            "",
            tails_pdp_common::StreamOperator::Equal,
            10,
            3,
        );

        assert_eq!(next_policy_time_boundary(11, &policy), Some(13));
        assert_eq!(next_policy_time_boundary(13, &policy), Some(14));
    }

    #[test]
    fn does_not_schedule_constant_time_conditions() {
        let policy = FileOpenStreamPolicy::time(
            Entitlement::Deny,
            1000,
            "",
            "",
            tails_pdp_common::StreamOperator::LessThan,
            10,
            0,
        );
        assert_eq!(next_policy_time_boundary(17, &policy), None);
    }

    #[tokio::test]
    async fn waits_without_scanning_when_no_trigger_arrives() {
        let (_sender, mut receiver) = mpsc::channel(1);
        let result = time::timeout(
            Duration::from_millis(20),
            wait_for_trigger(&mut receiver, None),
        )
        .await;
        assert!(result.is_err(), "a trigger-free PEP must remain idle");
    }

    #[tokio::test]
    async fn closed_trigger_channel_is_reported() {
        let (sender, mut receiver) = mpsc::channel(1);
        drop(sender);
        let error = wait_for_trigger(&mut receiver, None)
            .await
            .expect_err("closed channel must stop PEP explicitly");
        assert!(error.to_string().contains("trigger channel closed"));
    }
}

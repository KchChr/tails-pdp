use std::{
    collections::HashSet,
    env, fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, anyhow, bail};
use aya::maps::{Array, Map, MapData};
use log::{error, info};
use tails_pdp_common::{
    ANY_SUBJECT, COMMAND_LEN, Entitlement, FileOpenStaticPolicy, FileOpenStreamPolicy,
    POLICY_BANK_SIZE, PolicyAction, RESOURCE_LEN, SocketBindStaticPolicy, SocketBindStreamPolicy,
    SocketFamily, SocketTransport, StreamAttribute, StreamOperator, policy_bank_offset,
};
use tokio::time::{self, Duration};

use crate::BPF_PIN_DIRECTORY;

const POLICY_DIRECTORY_NAME: &str = "policies";
const POLICY_FILE_EXTENSION: &str = "sapl";
const POLICY_SCAN_INTERVAL: Duration = Duration::from_secs(1);

type FileOpenStaticPolicyMap = Array<MapData, FileOpenStaticPolicy>;
type FileOpenStreamPolicyMap = Array<MapData, FileOpenStreamPolicy>;
type SocketBindStaticPolicyMap = Array<MapData, SocketBindStaticPolicy>;
type SocketBindStreamPolicyMap = Array<MapData, SocketBindStreamPolicy>;
type PolicyGenerationMap = Array<MapData, u32>;

#[derive(Clone, Eq, PartialEq)]
struct PolicyDocument {
    relative_path: PathBuf,
    source: String,
}

#[derive(Default)]
struct CompiledPolicies {
    file_open_static: Vec<FileOpenStaticPolicy>,
    file_open_stream: Vec<FileOpenStreamPolicy>,
    socket_bind_static: Vec<SocketBindStaticPolicy>,
    socket_bind_stream: Vec<SocketBindStreamPolicy>,
}

#[derive(Copy, Clone)]
enum ParsedTimeCondition {
    TimeModulo {
        operator: StreamOperator,
        modulo: u64,
        value: u64,
    },
    Hour {
        operator: StreamOperator,
        value: u64,
    },
    Minute {
        operator: StreamOperator,
        value: u64,
    },
    Second {
        operator: StreamOperator,
        value: u64,
    },
}

struct ParsedPolicy {
    source_path: PathBuf,
    name: String,
    entitlement: Entitlement,
    action: PolicyAction,
    subject: u32,
    command: Option<String>,
    file_resource: Option<String>,
    socket_family: SocketFamily,
    socket_transport: SocketTransport,
    socket_resource: Option<String>,
    socket_port: u16,
    time_condition: Option<ParsedTimeCondition>,
}

struct PinnedPolicyMaps {
    policy_generation: PolicyGenerationMap,
    file_open_static: FileOpenStaticPolicyMap,
    file_open_stream: FileOpenStreamPolicyMap,
    socket_bind_static: SocketBindStaticPolicyMap,
    socket_bind_stream: SocketBindStreamPolicyMap,
}

pub struct PolicyDirectorySync {
    policy_dir: PathBuf,
    maps: PinnedPolicyMaps,
    last_applied_documents: Option<Vec<PolicyDocument>>,
    last_failed_documents: Option<Vec<PolicyDocument>>,
}

impl PolicyDirectorySync {
    pub fn new() -> anyhow::Result<Self> {
        let policy_dir = default_policy_directory()?;
        fs::create_dir_all(&policy_dir).with_context(|| {
            format!(
                "failed to create policy directory '{}'",
                policy_dir.display()
            )
        })?;

        Ok(Self {
            policy_dir,
            maps: PinnedPolicyMaps::open()?,
            last_applied_documents: None,
            last_failed_documents: None,
        })
    }

    pub fn directory(&self) -> &Path {
        &self.policy_dir
    }

    pub fn sync_initial(&mut self) -> anyhow::Result<()> {
        let documents = read_policy_documents(&self.policy_dir)?;
        match compile_policy_documents(&documents).and_then(|compiled| {
            let generation = self.maps.commit(&compiled)?;
            Ok((compiled, generation))
        }) {
            Ok((compiled, generation)) => {
                self.last_applied_documents = Some(documents);
                self.last_failed_documents = None;
                print_policy_summary(&self.policy_dir, generation, &compiled);
            }
            Err(error) => {
                error!(
                    "POLICY initial sync failed for '{}'; keeping existing pinned generation active: {error:#}",
                    self.policy_dir.display()
                );
                self.last_failed_documents = Some(documents);
            }
        }
        Ok(())
    }

    pub async fn run(mut self) -> anyhow::Result<()> {
        let mut interval = time::interval(POLICY_SCAN_INTERVAL);
        interval.tick().await;

        loop {
            interval.tick().await;
            self.sync_if_changed()?;
        }
    }

    fn sync_if_changed(&mut self) -> anyhow::Result<()> {
        let documents = read_policy_documents(&self.policy_dir)?;
        if self.last_applied_documents.as_ref() == Some(&documents)
            || self.last_failed_documents.as_ref() == Some(&documents)
        {
            return Ok(());
        }

        match compile_policy_documents(&documents).and_then(|compiled| {
            let generation = self.maps.commit(&compiled)?;
            Ok((compiled, generation))
        }) {
            Ok((compiled, generation)) => {
                self.last_applied_documents = Some(documents);
                self.last_failed_documents = None;
                print_policy_summary(&self.policy_dir, generation, &compiled);
            }
            Err(error) => {
                error!(
                    "POLICY sync failed for '{}'; previous generation remains active: {error:#}",
                    self.policy_dir.display()
                );
                self.last_failed_documents = Some(documents);
            }
        }
        Ok(())
    }
}

impl PinnedPolicyMaps {
    fn open() -> anyhow::Result<Self> {
        Ok(Self {
            policy_generation: open_array_map("POLICY_GENERATION")?,
            file_open_static: open_array_map("FILE_OPEN_STATIC_POLICIES")?,
            file_open_stream: open_array_map("FILE_OPEN_STREAM_POLICIES")?,
            socket_bind_static: open_array_map("SOCKET_BIND_STATIC_POLICIES")?,
            socket_bind_stream: open_array_map("SOCKET_BIND_STREAM_POLICIES")?,
        })
    }

    fn active_generation(&self) -> anyhow::Result<u32> {
        self.policy_generation
            .get(&0, 0)
            .context("failed to read POLICY_GENERATION[0]")
    }

    fn commit(&mut self, compiled: &CompiledPolicies) -> anyhow::Result<u32> {
        let current_generation = self.active_generation()?;
        let next_generation = current_generation.wrapping_add(1);
        let bank_offset = policy_bank_offset(next_generation);

        // Write the inactive bank first. The old generation remains active unless this final
        // POLICY_GENERATION write succeeds.
        self.write_bank(compiled, bank_offset)?;
        self.policy_generation
            .set(0, next_generation, 0)
            .context("failed to commit POLICY_GENERATION[0]")?;

        Ok(next_generation)
    }

    fn write_bank(&mut self, compiled: &CompiledPolicies, bank_offset: u32) -> anyhow::Result<()> {
        write_array_bank(
            &mut self.file_open_static,
            &compiled.file_open_static,
            FileOpenStaticPolicy::disabled(),
            "FILE_OPEN_STATIC_POLICIES",
            bank_offset,
        )?;
        write_array_bank(
            &mut self.file_open_stream,
            &compiled.file_open_stream,
            FileOpenStreamPolicy::disabled(),
            "FILE_OPEN_STREAM_POLICIES",
            bank_offset,
        )?;
        write_array_bank(
            &mut self.socket_bind_static,
            &compiled.socket_bind_static,
            SocketBindStaticPolicy::disabled(),
            "SOCKET_BIND_STATIC_POLICIES",
            bank_offset,
        )?;
        write_array_bank(
            &mut self.socket_bind_stream,
            &compiled.socket_bind_stream,
            SocketBindStreamPolicy::disabled(),
            "SOCKET_BIND_STREAM_POLICIES",
            bank_offset,
        )?;
        Ok(())
    }
}

pub fn default_policy_directory() -> anyhow::Result<PathBuf> {
    Ok(env::current_dir()
        .context("failed to determine current working directory")?
        .join(POLICY_DIRECTORY_NAME))
}

fn open_array_map<T: aya::Pod>(map_name: &str) -> anyhow::Result<Array<MapData, T>> {
    let pin_path = Path::new(BPF_PIN_DIRECTORY).join(map_name);
    let map_data = MapData::from_pin(&pin_path)
        .with_context(|| format!("failed to open pinned map '{}'", pin_path.display()))?;
    let map = Map::Array(map_data);
    Array::try_from(map).with_context(|| format!("failed to open {map_name} as array map"))
}

fn write_array_bank<T: aya::Pod + Copy>(
    map: &mut Array<MapData, T>,
    values: &[T],
    disabled: T,
    map_name: &str,
    bank_offset: u32,
) -> anyhow::Result<()> {
    if values.len() > POLICY_BANK_SIZE as usize {
        bail!(
            "too many policies for {}: {} > {}",
            map_name,
            values.len(),
            POLICY_BANK_SIZE
        );
    }

    if bank_offset + POLICY_BANK_SIZE > map.len() {
        bail!(
            "policy bank out of range for {}: bank_offset={} bank_size={} map_len={}",
            map_name,
            bank_offset,
            POLICY_BANK_SIZE,
            map.len()
        );
    }

    for index in 0..POLICY_BANK_SIZE {
        let value = values.get(index as usize).copied().unwrap_or(disabled);
        let map_index = bank_offset + index;
        map.set(map_index, value, 0)
            .with_context(|| format!("failed to write {map_name}[{map_index}]"))?;
    }

    Ok(())
}

fn read_policy_documents(policy_dir: &Path) -> anyhow::Result<Vec<PolicyDocument>> {
    let mut documents = Vec::new();
    read_policy_documents_recursive(policy_dir, policy_dir, &mut documents)?;
    documents.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    Ok(documents)
}

fn read_policy_documents_recursive(
    root: &Path,
    current: &Path,
    documents: &mut Vec<PolicyDocument>,
) -> anyhow::Result<()> {
    let mut entries = fs::read_dir(current)
        .with_context(|| format!("failed to read policy directory '{}'", current.display()))?
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("failed to iterate policy directory '{}'", current.display()))?;
    entries.sort_by_key(|entry| entry.path());

    for entry in entries {
        let path = entry.path();
        if path.is_dir() {
            read_policy_documents_recursive(root, &path, documents)?;
            continue;
        }

        if path.extension().and_then(|ext| ext.to_str()) != Some(POLICY_FILE_EXTENSION) {
            continue;
        }

        let source = fs::read_to_string(&path)
            .with_context(|| format!("failed to read policy file '{}'", path.display()))?;
        let relative_path = path
            .strip_prefix(root)
            .with_context(|| {
                format!(
                    "failed to create relative path for policy file '{}'",
                    path.display()
                )
            })?
            .to_path_buf();
        documents.push(PolicyDocument {
            relative_path,
            source,
        });
    }

    Ok(())
}

fn compile_policy_documents(documents: &[PolicyDocument]) -> anyhow::Result<CompiledPolicies> {
    let mut names = HashSet::new();
    let mut compiled = CompiledPolicies::default();

    for document in documents {
        let parsed = parse_policy_document(document)?;
        if !names.insert(parsed.name.clone()) {
            bail!(
                "duplicate policy name '{}' in '{}'",
                parsed.name,
                document.relative_path.display()
            );
        }
        compile_policy(&mut compiled, parsed)?;
    }

    Ok(compiled)
}

fn parse_policy_document(document: &PolicyDocument) -> anyhow::Result<ParsedPolicy> {
    let mut lines = document
        .source
        .lines()
        .enumerate()
        .filter_map(|(line_no, line)| {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with("//") || trimmed.starts_with('#') {
                return None;
            }
            Some((line_no + 1, trimmed.to_string()))
        });

    let (policy_line_no, policy_line) = lines.next().ok_or_else(|| {
        anyhow!(
            "policy file '{}' is empty",
            document.relative_path.display()
        )
    })?;
    let name = parse_policy_name(&policy_line).with_context(|| {
        format!(
            "{}:{}: invalid policy header",
            document.relative_path.display(),
            policy_line_no
        )
    })?;

    let (entitlement_line_no, entitlement_line) = lines.next().ok_or_else(|| {
        anyhow!(
            "{}:{}: missing entitlement line after policy header",
            document.relative_path.display(),
            policy_line_no
        )
    })?;
    let entitlement = parse_entitlement(&entitlement_line).with_context(|| {
        format!(
            "{}:{}: invalid entitlement line",
            document.relative_path.display(),
            entitlement_line_no
        )
    })?;

    let mut action = None;
    let mut subject = None;
    let mut command = None;
    let mut file_resource = None;
    let mut socket_family = None;
    let mut socket_transport = None;
    let mut socket_resource = None;
    let mut socket_port = None;
    let mut time_condition = None;

    for (line_no, line) in lines {
        let statement = line.strip_suffix(';').ok_or_else(|| {
            anyhow!(
                "{}:{}: policy statements must end with ';'",
                document.relative_path.display(),
                line_no
            )
        })?;

        if let Some(parsed_action) = parse_action_statement(statement)? {
            set_once(
                &mut action,
                parsed_action,
                &document.relative_path,
                line_no,
                "action",
            )?;
            continue;
        }

        if let Some(parsed_subject) = parse_subject_statement(statement)? {
            set_once(
                &mut subject,
                parsed_subject,
                &document.relative_path,
                line_no,
                "subject.uid",
            )?;
            continue;
        }

        if let Some(parsed_command) = parse_string_equality(statement, "command")? {
            set_once(
                &mut command,
                parsed_command,
                &document.relative_path,
                line_no,
                "command",
            )?;
            continue;
        }

        if let Some(parsed_resource) = parse_string_equality(statement, "resource.path")? {
            set_once(
                &mut file_resource,
                parsed_resource,
                &document.relative_path,
                line_no,
                "resource.path",
            )?;
            continue;
        }

        if let Some(parsed_family) = parse_socket_family_statement(statement)? {
            set_once(
                &mut socket_family,
                parsed_family,
                &document.relative_path,
                line_no,
                "resource.family",
            )?;
            continue;
        }

        if let Some(parsed_transport) = parse_socket_transport_statement(statement)? {
            set_once(
                &mut socket_transport,
                parsed_transport,
                &document.relative_path,
                line_no,
                "resource.transport",
            )?;
            continue;
        }

        if let Some(parsed_ip) = parse_string_equality(statement, "resource.ip")? {
            set_once(
                &mut socket_resource,
                parsed_ip,
                &document.relative_path,
                line_no,
                "resource.ip",
            )?;
            continue;
        }

        if let Some(parsed_port) = parse_port_statement(statement)? {
            set_once(
                &mut socket_port,
                parsed_port,
                &document.relative_path,
                line_no,
                "resource.port",
            )?;
            continue;
        }

        if let Some(parsed_time_condition) = parse_time_condition(statement)? {
            set_once(
                &mut time_condition,
                parsed_time_condition,
                &document.relative_path,
                line_no,
                "time condition",
            )?;
            continue;
        }

        bail!(
            "{}:{}: unsupported statement '{}'",
            document.relative_path.display(),
            line_no,
            statement
        );
    }

    let action = action.ok_or_else(|| {
        anyhow!(
            "{}: policy '{}' is missing 'action == ...'",
            document.relative_path.display(),
            name
        )
    })?;

    Ok(ParsedPolicy {
        source_path: document.relative_path.clone(),
        name,
        entitlement,
        action,
        subject: subject.unwrap_or(ANY_SUBJECT),
        command,
        file_resource,
        socket_family: socket_family.unwrap_or(SocketFamily::Any),
        socket_transport: socket_transport.unwrap_or(SocketTransport::Any),
        socket_resource,
        socket_port: socket_port.unwrap_or(0),
        time_condition,
    })
}

fn compile_policy(compiled: &mut CompiledPolicies, parsed: ParsedPolicy) -> anyhow::Result<()> {
    match (parsed.action, parsed.time_condition) {
        (PolicyAction::FileOpen, None) => {
            ensure_no_socket_fields(&parsed)?;
            let command = parsed.command.as_deref().unwrap_or("");
            let resource = parsed.file_resource.as_deref().unwrap_or("");
            ensure_string_len(command, COMMAND_LEN, "command", &parsed)?;
            ensure_string_len(resource, RESOURCE_LEN, "resource.path", &parsed)?;
            let policy =
                FileOpenStaticPolicy::new(parsed.entitlement, parsed.subject, command, resource)
                    .resolve_resource_identity()
                    .with_context(|| {
                        format!(
                            "failed to resolve file_open static resource in '{}'",
                            parsed.source_path.display()
                        )
                    })?;
            compiled.file_open_static.push(policy);
        }
        (PolicyAction::FileOpen, Some(time_condition)) => {
            ensure_no_socket_fields(&parsed)?;
            if parsed.command.is_some() {
                bail!(
                    "policy '{}' in '{}' cannot use 'command' with file_open stream policies",
                    parsed.name,
                    parsed.source_path.display()
                );
            }
            let resource = parsed.file_resource.as_deref().unwrap_or("");
            ensure_string_len(resource, RESOURCE_LEN, "resource.path", &parsed)?;
            let mut policy = FileOpenStreamPolicy::time(
                parsed.entitlement,
                parsed.subject,
                resource,
                stream_operator(time_condition),
                stream_modulo(time_condition),
                stream_value(time_condition),
            )
            .resolve_resource_identity()
            .with_context(|| {
                format!(
                    "failed to resolve file_open stream resource in '{}'",
                    parsed.source_path.display()
                )
            })?;
            policy.attribute = stream_attribute(time_condition);
            compiled.file_open_stream.push(policy);
        }
        (PolicyAction::SocketBind, None) => {
            ensure_no_file_open_fields(&parsed)?;
            let resource = parsed.socket_resource.as_deref().unwrap_or("");
            ensure_string_len(resource, RESOURCE_LEN, "resource.ip", &parsed)?;
            let policy = SocketBindStaticPolicy::new(
                parsed.entitlement,
                parsed.subject,
                parsed.socket_family,
                parsed.socket_transport,
                parsed.socket_port,
                resource,
            )
            .resolve_resource_identity()
            .with_context(|| {
                format!(
                    "failed to resolve socket_bind static resource in '{}'",
                    parsed.source_path.display()
                )
            })?;
            compiled.socket_bind_static.push(policy);
        }
        (PolicyAction::SocketBind, Some(time_condition)) => {
            ensure_no_file_open_fields(&parsed)?;
            let resource = parsed.socket_resource.as_deref().unwrap_or("");
            ensure_string_len(resource, RESOURCE_LEN, "resource.ip", &parsed)?;
            let mut policy = SocketBindStreamPolicy::time(
                parsed.entitlement,
                parsed.subject,
                parsed.socket_family,
                parsed.socket_transport,
                parsed.socket_port,
                resource,
                stream_operator(time_condition),
                stream_modulo(time_condition),
                stream_value(time_condition),
            )
            .resolve_resource_identity()
            .with_context(|| {
                format!(
                    "failed to resolve socket_bind stream resource in '{}'",
                    parsed.source_path.display()
                )
            })?;
            policy.attribute = stream_attribute(time_condition);
            compiled.socket_bind_stream.push(policy);
        }
    }

    ensure_policy_capacity(
        compiled.file_open_static.len(),
        compiled.file_open_stream.len(),
        compiled.socket_bind_static.len(),
        compiled.socket_bind_stream.len(),
    )?;

    Ok(())
}

fn ensure_policy_capacity(
    file_open_static_count: usize,
    file_open_stream_count: usize,
    socket_bind_static_count: usize,
    socket_bind_stream_count: usize,
) -> anyhow::Result<()> {
    if file_open_static_count > POLICY_BANK_SIZE as usize {
        bail!(
            "too many file_open static policies: {} > {}",
            file_open_static_count,
            POLICY_BANK_SIZE
        );
    }
    if file_open_stream_count > POLICY_BANK_SIZE as usize {
        bail!(
            "too many file_open stream policies: {} > {}",
            file_open_stream_count,
            POLICY_BANK_SIZE
        );
    }
    if socket_bind_static_count > POLICY_BANK_SIZE as usize {
        bail!(
            "too many socket_bind static policies: {} > {}",
            socket_bind_static_count,
            POLICY_BANK_SIZE
        );
    }
    if socket_bind_stream_count > POLICY_BANK_SIZE as usize {
        bail!(
            "too many socket_bind stream policies: {} > {}",
            socket_bind_stream_count,
            POLICY_BANK_SIZE
        );
    }
    Ok(())
}

fn ensure_string_len(
    value: &str,
    max_len: usize,
    label: &str,
    policy: &ParsedPolicy,
) -> anyhow::Result<()> {
    if value.len() > max_len {
        bail!(
            "policy '{}' in '{}' has {} longer than {} bytes",
            policy.name,
            policy.source_path.display(),
            label,
            max_len
        );
    }
    Ok(())
}

fn ensure_no_socket_fields(policy: &ParsedPolicy) -> anyhow::Result<()> {
    if policy.socket_family != SocketFamily::Any
        || policy.socket_transport != SocketTransport::Any
        || policy.socket_resource.is_some()
        || policy.socket_port != 0
    {
        bail!(
            "policy '{}' in '{}' uses socket_bind-only fields with action file_open",
            policy.name,
            policy.source_path.display()
        );
    }
    Ok(())
}

fn ensure_no_file_open_fields(policy: &ParsedPolicy) -> anyhow::Result<()> {
    if policy.command.is_some() || policy.file_resource.is_some() {
        bail!(
            "policy '{}' in '{}' uses file_open-only fields with action socket_bind",
            policy.name,
            policy.source_path.display()
        );
    }
    Ok(())
}

fn parse_policy_name(line: &str) -> anyhow::Result<String> {
    let remainder = line
        .strip_prefix("policy ")
        .ok_or_else(|| anyhow!("policy line must start with 'policy '"))?
        .trim();
    parse_quoted_string(remainder)
}

fn parse_entitlement(line: &str) -> anyhow::Result<Entitlement> {
    match line.trim() {
        "permit" => Ok(Entitlement::Permit),
        "deny" => Ok(Entitlement::Deny),
        other => bail!("unsupported entitlement '{other}'"),
    }
}

fn parse_action_statement(statement: &str) -> anyhow::Result<Option<PolicyAction>> {
    let Some(value) = parse_string_equality(statement, "action")? else {
        return Ok(None);
    };
    match value.as_str() {
        "file_open" | "file-open" => Ok(Some(PolicyAction::FileOpen)),
        "socket_bind" | "socket-bind" => Ok(Some(PolicyAction::SocketBind)),
        other => bail!("unsupported action '{other}'"),
    }
}

fn parse_subject_statement(statement: &str) -> anyhow::Result<Option<u32>> {
    let Some(raw) = parse_equality_rhs(statement, "subject.uid") else {
        return Ok(None);
    };
    Ok(Some(raw.parse().map_err(|error| {
        anyhow!("invalid subject.uid '{raw}': {error}")
    })?))
}

fn parse_socket_family_statement(statement: &str) -> anyhow::Result<Option<SocketFamily>> {
    let Some(value) = parse_string_equality(statement, "resource.family")? else {
        return Ok(None);
    };
    match value.as_str() {
        "any" => Ok(Some(SocketFamily::Any)),
        "inet" => Ok(Some(SocketFamily::Inet)),
        "inet6" => Ok(Some(SocketFamily::Inet6)),
        other => bail!("unsupported resource.family '{other}'"),
    }
}

fn parse_socket_transport_statement(statement: &str) -> anyhow::Result<Option<SocketTransport>> {
    let Some(value) = parse_string_equality(statement, "resource.transport")? else {
        return Ok(None);
    };
    match value.as_str() {
        "any" => Ok(Some(SocketTransport::Any)),
        "tcp" => Ok(Some(SocketTransport::Tcp)),
        "udp" => Ok(Some(SocketTransport::Udp)),
        other => bail!("unsupported resource.transport '{other}'"),
    }
}

fn parse_port_statement(statement: &str) -> anyhow::Result<Option<u16>> {
    let Some(raw) = parse_equality_rhs(statement, "resource.port") else {
        return Ok(None);
    };
    Ok(Some(raw.parse().map_err(|error| {
        anyhow!("invalid resource.port '{raw}': {error}")
    })?))
}

fn parse_time_condition(statement: &str) -> anyhow::Result<Option<ParsedTimeCondition>> {
    if let Some(remainder) = statement.strip_prefix("environment.time % ") {
        let tokens: Vec<_> = remainder.split_whitespace().collect();
        if tokens.len() != 3 {
            bail!("invalid environment.time modulo condition '{statement}'");
        }
        return Ok(Some(ParsedTimeCondition::TimeModulo {
            modulo: tokens[0]
                .parse()
                .map_err(|error| anyhow!("invalid modulo '{}': {error}", tokens[0]))?,
            operator: parse_stream_operator(tokens[1])?,
            value: tokens[2]
                .parse()
                .map_err(|error| anyhow!("invalid time value '{}': {error}", tokens[2]))?,
        }));
    }

    if let Some(remainder) = statement.strip_prefix("environment.utc.hour ") {
        return parse_component_time_condition(remainder, StreamAttribute::Hour).map(Some);
    }
    if let Some(remainder) = statement.strip_prefix("environment.utc.minute ") {
        return parse_component_time_condition(remainder, StreamAttribute::Minute).map(Some);
    }
    if let Some(remainder) = statement.strip_prefix("environment.utc.second ") {
        return parse_component_time_condition(remainder, StreamAttribute::Second).map(Some);
    }

    Ok(None)
}

fn parse_component_time_condition(
    remainder: &str,
    attribute: StreamAttribute,
) -> anyhow::Result<ParsedTimeCondition> {
    let tokens: Vec<_> = remainder.split_whitespace().collect();
    if tokens.len() != 2 {
        bail!("invalid time condition '{remainder}'");
    }

    let operator = parse_stream_operator(tokens[0])?;
    let value = tokens[1]
        .parse()
        .map_err(|error| anyhow!("invalid time component value '{}': {error}", tokens[1]))?;

    match attribute {
        StreamAttribute::Hour => Ok(ParsedTimeCondition::Hour { operator, value }),
        StreamAttribute::Minute => Ok(ParsedTimeCondition::Minute { operator, value }),
        StreamAttribute::Second => Ok(ParsedTimeCondition::Second { operator, value }),
        StreamAttribute::Time => bail!("unexpected StreamAttribute::Time"),
    }
}

fn parse_stream_operator(raw: &str) -> anyhow::Result<StreamOperator> {
    match raw {
        "<" => Ok(StreamOperator::LessThan),
        "<=" => Ok(StreamOperator::LessThanOrEqual),
        "==" => Ok(StreamOperator::Equal),
        ">=" => Ok(StreamOperator::GreaterThanOrEqual),
        ">" => Ok(StreamOperator::GreaterThan),
        other => bail!("unsupported operator '{other}'"),
    }
}

fn parse_string_equality(statement: &str, key: &str) -> anyhow::Result<Option<String>> {
    let Some(raw) = parse_equality_rhs(statement, key) else {
        return Ok(None);
    };
    parse_quoted_string(raw).map(Some)
}

fn parse_equality_rhs<'a>(statement: &'a str, key: &str) -> Option<&'a str> {
    let (lhs, rhs) = statement.split_once("==")?;
    if lhs.trim() != key {
        return None;
    }
    Some(rhs.trim())
}

fn parse_quoted_string(raw: &str) -> anyhow::Result<String> {
    if !raw.starts_with('"') || !raw.ends_with('"') || raw.len() < 2 {
        bail!("expected quoted string, got '{raw}'");
    }
    Ok(raw[1..raw.len() - 1].to_string())
}

fn set_once<T>(
    slot: &mut Option<T>,
    value: T,
    path: &Path,
    line_no: usize,
    label: &str,
) -> anyhow::Result<()> {
    if slot.is_some() {
        bail!("{}:{}: duplicate {}", path.display(), line_no, label);
    }
    *slot = Some(value);
    Ok(())
}

fn stream_attribute(condition: ParsedTimeCondition) -> StreamAttribute {
    match condition {
        ParsedTimeCondition::TimeModulo { .. } => StreamAttribute::Time,
        ParsedTimeCondition::Hour { .. } => StreamAttribute::Hour,
        ParsedTimeCondition::Minute { .. } => StreamAttribute::Minute,
        ParsedTimeCondition::Second { .. } => StreamAttribute::Second,
    }
}

fn stream_operator(condition: ParsedTimeCondition) -> StreamOperator {
    match condition {
        ParsedTimeCondition::TimeModulo { operator, .. }
        | ParsedTimeCondition::Hour { operator, .. }
        | ParsedTimeCondition::Minute { operator, .. }
        | ParsedTimeCondition::Second { operator, .. } => operator,
    }
}

fn stream_modulo(condition: ParsedTimeCondition) -> u64 {
    match condition {
        ParsedTimeCondition::TimeModulo { modulo, .. } => modulo,
        ParsedTimeCondition::Hour { .. }
        | ParsedTimeCondition::Minute { .. }
        | ParsedTimeCondition::Second { .. } => 0,
    }
}

fn stream_value(condition: ParsedTimeCondition) -> u64 {
    match condition {
        ParsedTimeCondition::TimeModulo { value, .. }
        | ParsedTimeCondition::Hour { value, .. }
        | ParsedTimeCondition::Minute { value, .. }
        | ParsedTimeCondition::Second { value, .. } => value,
    }
}

fn print_policy_summary(policy_dir: &Path, generation: u32, compiled: &CompiledPolicies) {
    info!(
        "POLICY sync ok dir={} generation={} file_open_static={} file_open_stream={} socket_bind_static={} socket_bind_stream={}",
        policy_dir.display(),
        generation,
        compiled.file_open_static.len(),
        compiled.file_open_stream.len(),
        compiled.socket_bind_static.len(),
        compiled.socket_bind_stream.len(),
    );
}

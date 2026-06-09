use std::{
    collections::HashSet,
    env, fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, anyhow, bail};
use aya::maps::{Array, Map, MapData};
use log::{error, info};
use tails_pdp_common::{
    ANY_SUBJECT, AttributeCondition, AttributeNamespace, AttributeValueKind, COMMAND_LEN,
    DEFCON_MAX_LEVEL, DEFCON_MIN_LEVEL, Entitlement, FileOpenStaticPolicy, FileOpenStreamPolicy,
    MAX_ATTRIBUTE_CONDITIONS, POLICY_BANK_SIZE, PolicyAction, RESOURCE_LEN, SocketFamily,
    SocketTransport, StreamAttribute, StreamOperator, attribute_hash, policy_bank_offset,
};
use tokio::time::{Duration, sleep};

use crate::{BPF_PIN_DIRECTORY, fs_watch};

const POLICY_DIRECTORY_NAME: &str = "policies";
const POLICY_FILE_EXTENSION: &str = "sapl";
const POLICY_EVENT_DEBOUNCE: Duration = Duration::from_millis(100);

type FileOpenStaticPolicyMap = Array<MapData, FileOpenStaticPolicy>;
type FileOpenStreamPolicyMap = Array<MapData, FileOpenStreamPolicy>;
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
}

#[derive(Copy, Clone)]
enum ParsedStreamCondition {
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
    Defcon {
        operator: StreamOperator,
        value: u64,
    },
    Dynamic(AttributeCondition),
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
    stream_conditions: Vec<ParsedStreamCondition>,
}

struct PinnedPolicyMaps {
    policy_generation: PolicyGenerationMap,
    file_open_static: FileOpenStaticPolicyMap,
    file_open_stream: FileOpenStreamPolicyMap,
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
        let mut watcher = fs_watch::watch_directory_recursive(&self.policy_dir)?;

        loop {
            watcher.wait_for_change().await?;
            sleep(POLICY_EVENT_DEBOUNCE).await;
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
    let mut stream_conditions = Vec::new();

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

        if let Some(parsed_stream_condition) = parse_stream_condition(statement)? {
            stream_conditions.push(parsed_stream_condition);
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
        stream_conditions,
    })
}

fn compile_policy(compiled: &mut CompiledPolicies, parsed: ParsedPolicy) -> anyhow::Result<()> {
    if parsed.stream_conditions.is_empty() {
        match parsed.action {
            PolicyAction::FileOpen => {
                ensure_no_socket_fields(&parsed)?;
                let command = parsed.command.as_deref().unwrap_or("");
                let resource = parsed.file_resource.as_deref().unwrap_or("");
                ensure_string_len(command, COMMAND_LEN, "command", &parsed)?;
                ensure_string_len(resource, RESOURCE_LEN, "resource.path", &parsed)?;
                let policy = FileOpenStaticPolicy::new(
                    parsed.entitlement,
                    parsed.subject,
                    command,
                    resource,
                )
                .resolve_resource_identity()
                .with_context(|| {
                    format!(
                        "failed to resolve file_open static resource in '{}'",
                        parsed.source_path.display()
                    )
                })?;
                compiled.file_open_static.push(policy);
            }
            PolicyAction::SocketBind => bail_socket_bind_disabled(&parsed)?,
        }
    } else {
        let (legacy_condition, attribute_conditions) = split_stream_conditions(&parsed)?;
        match parsed.action {
            PolicyAction::FileOpen => {
                ensure_no_socket_fields(&parsed)?;
                let command = parsed.command.as_deref().unwrap_or("");
                let resource = parsed.file_resource.as_deref().unwrap_or("");
                ensure_string_len(command, COMMAND_LEN, "command", &parsed)?;
                ensure_string_len(resource, RESOURCE_LEN, "resource.path", &parsed)?;
                let mut policy = FileOpenStreamPolicy::stream(
                    parsed.entitlement,
                    parsed.subject,
                    command,
                    resource,
                )
                .resolve_resource_identity()
                .with_context(|| {
                    format!(
                        "failed to resolve file_open stream resource in '{}'",
                        parsed.source_path.display()
                    )
                })?;
                apply_legacy_stream_condition_file_open(&mut policy, legacy_condition);
                apply_attribute_conditions_file_open(&mut policy, &attribute_conditions);
                compiled.file_open_stream.push(policy);
            }
            PolicyAction::SocketBind => bail_socket_bind_disabled(&parsed)?,
        }
    }

    ensure_policy_capacity(
        compiled.file_open_static.len(),
        compiled.file_open_stream.len(),
    )?;

    Ok(())
}

fn ensure_policy_capacity(
    file_open_static_count: usize,
    file_open_stream_count: usize,
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
    Ok(())
}

fn bail_socket_bind_disabled(policy: &ParsedPolicy) -> anyhow::Result<()> {
    bail!(
        "policy '{}' in '{}' uses action socket_bind, but socket_bind support is currently disabled",
        policy.name,
        policy.source_path.display()
    )
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

fn parse_stream_condition(statement: &str) -> anyhow::Result<Option<ParsedStreamCondition>> {
    if let Some(remainder) = statement.strip_prefix("environment.time % ") {
        let tokens: Vec<_> = remainder.split_whitespace().collect();
        if tokens.len() != 3 {
            bail!("invalid environment.time modulo condition '{statement}'");
        }
        return Ok(Some(ParsedStreamCondition::TimeModulo {
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
        return parse_component_stream_condition(remainder, StreamAttribute::Hour).map(Some);
    }
    if let Some(remainder) = statement.strip_prefix("environment.utc.minute ") {
        return parse_component_stream_condition(remainder, StreamAttribute::Minute).map(Some);
    }
    if let Some(remainder) = statement.strip_prefix("environment.utc.second ") {
        return parse_component_stream_condition(remainder, StreamAttribute::Second).map(Some);
    }
    if let Some(remainder) = statement.strip_prefix("environment.defcon.level ") {
        return parse_component_stream_condition(remainder, StreamAttribute::Defcon).map(Some);
    }

    if let Some(condition) = parse_dynamic_attribute_condition(statement)? {
        return Ok(Some(ParsedStreamCondition::Dynamic(condition)));
    }

    Ok(None)
}

fn parse_dynamic_attribute_condition(
    statement: &str,
) -> anyhow::Result<Option<AttributeCondition>> {
    let Some((lhs, operator, rhs)) = parse_comparison_statement(statement)? else {
        return Ok(None);
    };

    let (namespace, attribute_name) = if let Some(attribute_name) = lhs.strip_prefix("subject.") {
        if attribute_name == "uid" {
            return Ok(None);
        }
        (AttributeNamespace::Subject, attribute_name)
    } else if let Some(attribute_name) = lhs.strip_prefix("system.") {
        (AttributeNamespace::System, attribute_name)
    } else {
        return Ok(None);
    };

    validate_dynamic_attribute_name(attribute_name)?;
    let (value_kind, value_number, value_hash) = parse_dynamic_attribute_value(rhs)?;
    if value_kind == AttributeValueKind::String && operator != StreamOperator::Equal {
        bail!("string attributes only support '==' comparisons");
    }

    Ok(Some(AttributeCondition {
        namespace,
        operator,
        value_kind,
        _pad: [0; 5],
        name_hash: attribute_hash(attribute_name),
        value_number,
        value_hash,
    }))
}

fn parse_comparison_statement(
    statement: &str,
) -> anyhow::Result<Option<(&str, StreamOperator, &str)>> {
    for (raw_operator, operator) in [
        ("<=", StreamOperator::LessThanOrEqual),
        (">=", StreamOperator::GreaterThanOrEqual),
        ("==", StreamOperator::Equal),
        ("<", StreamOperator::LessThan),
        (">", StreamOperator::GreaterThan),
    ] {
        if let Some((lhs, rhs)) = statement.split_once(raw_operator) {
            return Ok(Some((lhs.trim(), operator, rhs.trim())));
        }
    }

    Ok(None)
}

fn validate_dynamic_attribute_name(name: &str) -> anyhow::Result<()> {
    if name.is_empty() {
        bail!("attribute name must not be empty");
    }
    if !name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        bail!("attribute name '{name}' contains unsupported characters");
    }
    Ok(())
}

fn parse_dynamic_attribute_value(
    raw: &str,
) -> anyhow::Result<(AttributeValueKind, u64, tails_pdp_common::AttributeHash)> {
    if raw.starts_with('"') || raw.ends_with('"') {
        let value = parse_quoted_string(raw)?;
        return Ok((AttributeValueKind::String, 0, attribute_hash(&value)));
    }

    match raw {
        "true" => {
            return Ok((
                AttributeValueKind::Bool,
                1,
                tails_pdp_common::AttributeHash::zero(),
            ));
        }
        "false" => {
            return Ok((
                AttributeValueKind::Bool,
                0,
                tails_pdp_common::AttributeHash::zero(),
            ));
        }
        _ => {}
    }

    let number = raw
        .parse::<u64>()
        .with_context(|| format!("attribute value '{raw}' is not a number, bool, or string"))?;
    Ok((
        AttributeValueKind::Number,
        number,
        tails_pdp_common::AttributeHash::zero(),
    ))
}

fn parse_component_stream_condition(
    remainder: &str,
    attribute: StreamAttribute,
) -> anyhow::Result<ParsedStreamCondition> {
    let tokens: Vec<_> = remainder.split_whitespace().collect();
    if tokens.len() != 2 {
        bail!("invalid stream condition '{remainder}'");
    }

    let operator = parse_stream_operator(tokens[0])?;
    let value = tokens[1]
        .parse()
        .map_err(|error| anyhow!("invalid stream attribute value '{}': {error}", tokens[1]))?;

    if attribute == StreamAttribute::Defcon
        && !((DEFCON_MIN_LEVEL as u64)..=(DEFCON_MAX_LEVEL as u64)).contains(&value)
    {
        bail!("invalid DEFCON level {value}; expected {DEFCON_MIN_LEVEL}..={DEFCON_MAX_LEVEL}");
    }

    match attribute {
        StreamAttribute::Hour => Ok(ParsedStreamCondition::Hour { operator, value }),
        StreamAttribute::Minute => Ok(ParsedStreamCondition::Minute { operator, value }),
        StreamAttribute::Second => Ok(ParsedStreamCondition::Second { operator, value }),
        StreamAttribute::Defcon => Ok(ParsedStreamCondition::Defcon { operator, value }),
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

fn stream_attribute(condition: ParsedStreamCondition) -> StreamAttribute {
    match condition {
        ParsedStreamCondition::TimeModulo { .. } => StreamAttribute::Time,
        ParsedStreamCondition::Hour { .. } => StreamAttribute::Hour,
        ParsedStreamCondition::Minute { .. } => StreamAttribute::Minute,
        ParsedStreamCondition::Second { .. } => StreamAttribute::Second,
        ParsedStreamCondition::Defcon { .. } => StreamAttribute::Defcon,
        ParsedStreamCondition::Dynamic(_) => StreamAttribute::Time,
    }
}

fn stream_operator(condition: ParsedStreamCondition) -> StreamOperator {
    match condition {
        ParsedStreamCondition::TimeModulo { operator, .. }
        | ParsedStreamCondition::Hour { operator, .. }
        | ParsedStreamCondition::Minute { operator, .. }
        | ParsedStreamCondition::Second { operator, .. }
        | ParsedStreamCondition::Defcon { operator, .. } => operator,
        ParsedStreamCondition::Dynamic(condition) => condition.operator,
    }
}

fn stream_modulo(condition: ParsedStreamCondition) -> u64 {
    match condition {
        ParsedStreamCondition::TimeModulo { modulo, .. } => modulo,
        ParsedStreamCondition::Hour { .. }
        | ParsedStreamCondition::Minute { .. }
        | ParsedStreamCondition::Second { .. }
        | ParsedStreamCondition::Defcon { .. }
        | ParsedStreamCondition::Dynamic(_) => 0,
    }
}

fn stream_value(condition: ParsedStreamCondition) -> u64 {
    match condition {
        ParsedStreamCondition::TimeModulo { value, .. }
        | ParsedStreamCondition::Hour { value, .. }
        | ParsedStreamCondition::Minute { value, .. }
        | ParsedStreamCondition::Second { value, .. }
        | ParsedStreamCondition::Defcon { value, .. } => value,
        ParsedStreamCondition::Dynamic(_) => 0,
    }
}

fn split_stream_conditions(
    policy: &ParsedPolicy,
) -> anyhow::Result<(Option<ParsedStreamCondition>, Vec<AttributeCondition>)> {
    let mut legacy_condition = None;
    let mut attribute_conditions = Vec::new();

    for condition in policy.stream_conditions.iter().copied() {
        match condition {
            ParsedStreamCondition::Dynamic(attribute_condition) => {
                attribute_conditions.push(attribute_condition);
            }
            _ => {
                if legacy_condition.is_some() {
                    bail!(
                        "policy '{}' in '{}' uses more than one built-in stream condition",
                        policy.name,
                        policy.source_path.display()
                    );
                }
                legacy_condition = Some(condition);
            }
        }
    }

    if attribute_conditions.len() > MAX_ATTRIBUTE_CONDITIONS {
        bail!(
            "policy '{}' in '{}' uses too many dynamic attribute conditions: {} > {}",
            policy.name,
            policy.source_path.display(),
            attribute_conditions.len(),
            MAX_ATTRIBUTE_CONDITIONS
        );
    }

    Ok((legacy_condition, attribute_conditions))
}

fn apply_legacy_stream_condition_file_open(
    policy: &mut FileOpenStreamPolicy,
    condition: Option<ParsedStreamCondition>,
) {
    let Some(condition) = condition else {
        return;
    };
    policy.stream_condition_enabled = 1;
    policy.attribute = stream_attribute(condition);
    policy.operator = stream_operator(condition);
    policy.modulo = stream_modulo(condition);
    policy.value = stream_value(condition);
}

fn apply_attribute_conditions_file_open(
    policy: &mut FileOpenStreamPolicy,
    conditions: &[AttributeCondition],
) {
    policy.attribute_condition_count = conditions.len() as u8;
    for (index, condition) in conditions.iter().copied().enumerate() {
        policy.attribute_conditions[index] = condition;
    }
}

fn print_policy_summary(policy_dir: &Path, generation: u32, compiled: &CompiledPolicies) {
    info!(
        "POLICY sync ok dir={} generation={} file_open_static={} file_open_stream={}",
        policy_dir.display(),
        generation,
        compiled.file_open_static.len(),
        compiled.file_open_stream.len(),
    );
}

use std::{
    collections::HashSet,
    env, fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, anyhow, bail};
use aya::maps::{Array, MapData};
use log::{error, info};
use tails_pdp_common::{
    ANY_SUBJECT, AttributeCondition, AttributeNamespace, AttributeValueKind, COMMAND_LEN,
    Entitlement, FileOpenStaticPolicy, FileOpenStreamPolicy, MAX_ATTRIBUTE_CONDITIONS,
    POLICY_BANK_SIZE, PolicyAction, RESOURCE_LEN, SocketFamily, SocketTransport, StreamAttribute,
    StreamOperator, attribute_hash, policy_bank_offset,
};
use tails_pdp_userspace_common::{
    EnforcementTrigger, fs_watch, notify_enforcement, open_pinned_array,
};
use tokio::{
    sync::mpsc,
    time::{Duration, sleep},
};

const POLICY_DIRECTORY_NAME: &str = "policies";
const POLICY_FILE_EXTENSION: &str = "policy";
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
struct TranslatedPolicies {
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

trait PolicyGenerationStore {
    fn active_generation(&self) -> anyhow::Result<u32>;
    fn write_inactive_bank(
        &mut self,
        translated: &TranslatedPolicies,
        bank_offset: u32,
    ) -> anyhow::Result<()>;
    fn activate_generation(&mut self, generation: u32) -> anyhow::Result<()>;
}

pub struct PolicyDirectorySync {
    policy_dir: PathBuf,
    maps: PinnedPolicyMaps,
    last_applied_documents: Option<Vec<PolicyDocument>>,
    last_failed_documents: Option<Vec<PolicyDocument>>,
    enforcement_triggers: mpsc::Sender<EnforcementTrigger>,
}

impl PolicyDirectorySync {
    pub fn new(enforcement_triggers: mpsc::Sender<EnforcementTrigger>) -> anyhow::Result<Self> {
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
            enforcement_triggers,
        })
    }

    pub fn directory(&self) -> &Path {
        &self.policy_dir
    }

    pub fn sync_initial(&mut self) -> anyhow::Result<()> {
        let documents = read_policy_documents(&self.policy_dir)?;
        let translated = translate_policy_documents(&documents).with_context(|| {
            format!(
                "initial policy validation failed for '{}'",
                self.policy_dir.display()
            )
        })?;
        let generation = self.maps.commit(&translated).with_context(|| {
            format!(
                "initial policy commit failed for '{}'",
                self.policy_dir.display()
            )
        })?;
        self.last_applied_documents = Some(documents);
        self.last_failed_documents = None;
        print_policy_summary(&self.policy_dir, generation, &translated);
        self.notify_activation(generation)?;
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
        if !documents_need_sync(
            self.last_applied_documents.as_deref(),
            self.last_failed_documents.as_deref(),
            &documents,
        ) {
            return Ok(());
        }

        match translate_policy_documents(&documents).and_then(|translated| {
            let generation = self.maps.commit(&translated)?;
            Ok((translated, generation))
        }) {
            Ok((translated, generation)) => {
                self.last_applied_documents = Some(documents);
                self.last_failed_documents = None;
                print_policy_summary(&self.policy_dir, generation, &translated);
                self.notify_activation(generation)?;
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

    fn notify_activation(&self, generation: u32) -> anyhow::Result<()> {
        let trigger = EnforcementTrigger::PolicyGenerationActivated { generation };
        if notify_enforcement(&self.enforcement_triggers, trigger)? {
            info!(
                "POLICY generation={} activated; queued userspace PEP re-evaluation",
                generation
            );
        } else {
            info!(
                "POLICY generation={} activated; userspace PEP re-evaluation coalesced",
                generation
            );
        }
        Ok(())
    }
}

impl PinnedPolicyMaps {
    fn open() -> anyhow::Result<Self> {
        Ok(Self {
            policy_generation: open_pinned_array("POLICY_GENERATION")?,
            file_open_static: open_pinned_array("FILE_OPEN_STATIC_POLICIES")?,
            file_open_stream: open_pinned_array("FILE_OPEN_STREAM_POLICIES")?,
        })
    }

    fn commit(&mut self, translated: &TranslatedPolicies) -> anyhow::Result<u32> {
        commit_policy_generation(self, translated)
    }
}

impl PolicyGenerationStore for PinnedPolicyMaps {
    fn active_generation(&self) -> anyhow::Result<u32> {
        self.policy_generation
            .get(&0, 0)
            .context("failed to read POLICY_GENERATION[0]")
    }

    fn write_inactive_bank(
        &mut self,
        translated: &TranslatedPolicies,
        bank_offset: u32,
    ) -> anyhow::Result<()> {
        self.write_bank(translated, bank_offset)
    }

    fn activate_generation(&mut self, generation: u32) -> anyhow::Result<()> {
        self.policy_generation
            .set(0, generation, 0)
            .context("failed to commit POLICY_GENERATION[0]")
    }
}

fn commit_policy_generation<S: PolicyGenerationStore>(
    store: &mut S,
    translated: &TranslatedPolicies,
) -> anyhow::Result<u32> {
    let current_generation = store.active_generation()?;
    let next_generation = current_generation.wrapping_add(1);
    let bank_offset = policy_bank_offset(next_generation);

    // The inactive bank is always written first. A failed write therefore cannot expose a
    // partially updated policy set through POLICY_GENERATION.
    store.write_inactive_bank(translated, bank_offset)?;
    store.activate_generation(next_generation)?;

    Ok(next_generation)
}

fn documents_need_sync(
    last_applied: Option<&[PolicyDocument]>,
    last_failed: Option<&[PolicyDocument]>,
    current: &[PolicyDocument],
) -> bool {
    last_applied != Some(current) && last_failed != Some(current)
}

impl PinnedPolicyMaps {
    fn write_bank(
        &mut self,
        translated: &TranslatedPolicies,
        bank_offset: u32,
    ) -> anyhow::Result<()> {
        write_array_bank(
            &mut self.file_open_static,
            &translated.file_open_static,
            FileOpenStaticPolicy::disabled(),
            "FILE_OPEN_STATIC_POLICIES",
            bank_offset,
        )?;
        write_array_bank(
            &mut self.file_open_stream,
            &translated.file_open_stream,
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

fn write_array_bank<T: aya::Pod + Copy>(
    map: &mut Array<MapData, T>,
    values: &[T],
    disabled: T,
    map_name: &str,
    bank_offset: u32,
) -> anyhow::Result<()> {
    let prepared = prepare_array_bank(values, disabled, map_name)?;

    if bank_offset + POLICY_BANK_SIZE > map.len() {
        bail!(
            "policy bank out of range for {}: bank_offset={} bank_size={} map_len={}",
            map_name,
            bank_offset,
            POLICY_BANK_SIZE,
            map.len()
        );
    }

    for (index, value) in prepared.into_iter().enumerate() {
        let map_index = bank_offset + index as u32;
        map.set(map_index, value, 0)
            .with_context(|| format!("failed to write {map_name}[{map_index}]"))?;
    }

    Ok(())
}

fn prepare_array_bank<T: Copy>(
    values: &[T],
    disabled: T,
    map_name: &str,
) -> anyhow::Result<Vec<T>> {
    if values.len() > POLICY_BANK_SIZE as usize {
        bail!(
            "too many policies for {}: {} > {}",
            map_name,
            values.len(),
            POLICY_BANK_SIZE
        );
    }

    let mut prepared = vec![disabled; POLICY_BANK_SIZE as usize];
    prepared[..values.len()].copy_from_slice(values);
    Ok(prepared)
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

fn translate_policy_documents(documents: &[PolicyDocument]) -> anyhow::Result<TranslatedPolicies> {
    let mut names = HashSet::new();
    let mut translated = TranslatedPolicies::default();

    for document in documents {
        let parsed = parse_policy_document(document)?;
        if !names.insert(parsed.name.clone()) {
            bail!(
                "duplicate policy name '{}' in '{}'",
                parsed.name,
                document.relative_path.display()
            );
        }
        translate_policy(&mut translated, parsed)?;
    }

    Ok(translated)
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

fn translate_policy(
    translated: &mut TranslatedPolicies,
    parsed: ParsedPolicy,
) -> anyhow::Result<()> {
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
                translated.file_open_static.push(policy);
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
                translated.file_open_stream.push(policy);
            }
            PolicyAction::SocketBind => bail_socket_bind_disabled(&parsed)?,
        }
    }

    ensure_policy_capacity(
        translated.file_open_static.len(),
        translated.file_open_stream.len(),
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
        let modulo = tokens[0]
            .parse()
            .map_err(|error| anyhow!("invalid modulo '{}': {error}", tokens[0]))?;
        if modulo == 0 {
            bail!("environment.time modulo must be greater than zero");
        }
        return Ok(Some(ParsedStreamCondition::TimeModulo {
            modulo,
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
    } else if let Some(attribute_name) = lhs.strip_prefix("resource.") {
        if matches!(
            attribute_name,
            "path" | "family" | "transport" | "ip" | "port"
        ) {
            return Ok(None);
        }
        (AttributeNamespace::Resource, attribute_name)
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

    let maximum = match attribute {
        StreamAttribute::Hour => 23,
        StreamAttribute::Minute | StreamAttribute::Second => 59,
        StreamAttribute::Time => bail!("unexpected StreamAttribute::Time"),
    };
    if value > maximum {
        bail!(
            "stream attribute value {} is outside 0..={} for {:?}",
            value,
            maximum,
            attribute
        );
    }

    match attribute {
        StreamAttribute::Hour => Ok(ParsedStreamCondition::Hour { operator, value }),
        StreamAttribute::Minute => Ok(ParsedStreamCondition::Minute { operator, value }),
        StreamAttribute::Second => Ok(ParsedStreamCondition::Second { operator, value }),
        StreamAttribute::Time => unreachable!(),
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
        ParsedStreamCondition::Dynamic(_) => StreamAttribute::Time,
    }
}

fn stream_operator(condition: ParsedStreamCondition) -> StreamOperator {
    match condition {
        ParsedStreamCondition::TimeModulo { operator, .. }
        | ParsedStreamCondition::Hour { operator, .. }
        | ParsedStreamCondition::Minute { operator, .. }
        | ParsedStreamCondition::Second { operator, .. } => operator,
        ParsedStreamCondition::Dynamic(condition) => condition.operator,
    }
}

fn stream_modulo(condition: ParsedStreamCondition) -> u64 {
    match condition {
        ParsedStreamCondition::TimeModulo { modulo, .. } => modulo,
        ParsedStreamCondition::Hour { .. }
        | ParsedStreamCondition::Minute { .. }
        | ParsedStreamCondition::Second { .. }
        | ParsedStreamCondition::Dynamic(_) => 0,
    }
}

fn stream_value(condition: ParsedStreamCondition) -> u64 {
    match condition {
        ParsedStreamCondition::TimeModulo { value, .. }
        | ParsedStreamCondition::Hour { value, .. }
        | ParsedStreamCondition::Minute { value, .. }
        | ParsedStreamCondition::Second { value, .. } => value,
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

fn print_policy_summary(policy_dir: &Path, generation: u32, translated: &TranslatedPolicies) {
    info!(
        "POLICY sync ok dir={} generation={} file_open_static={} file_open_stream={}",
        policy_dir.display(),
        generation,
        translated.file_open_static.len(),
        translated.file_open_stream.len(),
    );
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    fn document(source: &str) -> PolicyDocument {
        PolicyDocument {
            relative_path: PathBuf::from("test.policy"),
            source: source.to_owned(),
        }
    }

    fn translation_error(documents: &[PolicyDocument]) -> String {
        match translate_policy_documents(documents) {
            Ok(_) => panic!("policy translation should fail"),
            Err(error) => format!("{error:#}"),
        }
    }

    fn static_policy(name: &str) -> PolicyDocument {
        document(&format!(
            "policy \"{name}\"\ndeny\n    action == \"file_open\";\n"
        ))
    }

    struct FakePolicyStore {
        generation: u32,
        events: Vec<String>,
        fail_write: bool,
        fail_activation: bool,
    }

    impl FakePolicyStore {
        fn new(generation: u32) -> Self {
            Self {
                generation,
                events: Vec::new(),
                fail_write: false,
                fail_activation: false,
            }
        }
    }

    impl PolicyGenerationStore for FakePolicyStore {
        fn active_generation(&self) -> anyhow::Result<u32> {
            Ok(self.generation)
        }

        fn write_inactive_bank(
            &mut self,
            _translated: &TranslatedPolicies,
            bank_offset: u32,
        ) -> anyhow::Result<()> {
            self.events.push(format!("write-bank:{bank_offset}"));
            if self.fail_write {
                bail!("injected bank write failure");
            }
            Ok(())
        }

        fn activate_generation(&mut self, generation: u32) -> anyhow::Result<()> {
            self.events.push(format!("activate:{generation}"));
            if self.fail_activation {
                bail!("injected generation activation failure");
            }
            self.generation = generation;
            Ok(())
        }
    }

    #[test]
    fn translates_dynamic_subject_attribute() {
        let translated = translate_policy_documents(&[document(
            r#"
            policy "engineers only"
            permit
                action == "file_open";
                subject.position == "engineer";
            "#,
        )])
        .expect("policy should be translated");

        assert!(translated.file_open_static.is_empty());
        assert_eq!(translated.file_open_stream.len(), 1);
        let policy = translated.file_open_stream[0];
        assert_eq!(policy.attribute_condition_count, 1);
        assert_eq!(
            policy.attribute_conditions[0].name_hash,
            attribute_hash("position")
        );
    }

    #[test]
    fn rejects_unsupported_attribute_name() {
        let result = translate_policy_documents(&[document(
            r#"
            policy "invalid attribute"
            permit
                action == "file_open";
                subject.clearance.level == 3;
            "#,
        )]);
        let error = match result {
            Ok(_) => panic!("attribute name should be rejected"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("unsupported characters"));
    }

    #[test]
    fn translates_static_and_time_policies() {
        let translated = translate_policy_documents(&[
            static_policy("static deny"),
            document(
                r#"
                policy "time deny"
                deny
                    action == "file_open";
                    environment.utc.hour < 8;
                "#,
            ),
        ])
        .expect("valid policies should translate");

        assert_eq!(translated.file_open_static.len(), 1);
        assert_eq!(translated.file_open_stream.len(), 1);
        assert_eq!(
            translated.file_open_stream[0].attribute,
            StreamAttribute::Hour
        );
    }

    #[test]
    fn rejects_duplicate_policy_names() {
        let error = translation_error(&[static_policy("duplicate"), static_policy("duplicate")]);
        assert!(error.contains("duplicate policy name"));
    }

    #[test]
    fn rejects_missing_semicolon_and_unknown_action() {
        let missing_semicolon = translation_error(&[document(
            "policy \"missing semicolon\"\ndeny\n    action == \"file_open\"\n",
        )]);
        assert!(missing_semicolon.contains("must end with ';'"));

        let unknown_action = translation_error(&[document(
            "policy \"unknown action\"\ndeny\n    action == \"process_exec\";\n",
        )]);
        assert!(unknown_action.contains("unsupported action"));
    }

    #[test]
    fn rejects_disabled_socket_bind_action() {
        let error = translation_error(&[document(
            "policy \"socket\"\ndeny\n    action == \"socket_bind\";\n",
        )]);
        assert!(error.contains("socket_bind support is currently disabled"));
    }

    #[test]
    fn rejects_too_many_dynamic_conditions_and_policies() {
        let too_many_conditions = translation_error(&[document(
            r#"
            policy "too many conditions"
            deny
                action == "file_open";
                subject.attr1 == 1;
                subject.attr2 == 2;
                subject.attr3 == 3;
                subject.attr4 == 4;
                subject.attr5 == 5;
            "#,
        )]);
        assert!(too_many_conditions.contains("too many dynamic attribute conditions"));

        let documents: Vec<_> = (0..=POLICY_BANK_SIZE)
            .map(|index| static_policy(&format!("policy {index}")))
            .collect();
        let too_many_policies = translation_error(&documents);
        assert!(too_many_policies.contains("too many file_open static policies"));
    }

    #[test]
    fn rejects_invalid_time_ranges_and_zero_modulo() {
        for condition in [
            "environment.utc.hour == 24;",
            "environment.utc.minute == 60;",
            "environment.utc.second == 60;",
            "environment.time % 0 == 0;",
        ] {
            let error = translation_error(&[document(&format!(
                "policy \"invalid time\"\ndeny\n    action == \"file_open\";\n    {condition}\n"
            ))]);
            assert!(
                error.contains("outside") || error.contains("greater than zero"),
                "unexpected error for {condition}: {error}"
            );
        }
    }

    #[test]
    fn reads_only_policy_files_recursively() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "tails-pdp-policy-loader-test-{}-{unique}",
            std::process::id()
        ));
        let nested = root.join("nested");
        fs::create_dir_all(&nested).expect("create temporary policy directory");
        fs::write(root.join("ignored.txt"), "not a policy").expect("write ignored file");
        fs::write(
            nested.join("accepted.policy"),
            "policy \"accepted\"\npermit\n",
        )
        .expect("write policy file");

        let documents = read_policy_documents(&root).expect("read policy directory");
        fs::remove_dir_all(&root).expect("remove temporary policy directory");

        assert_eq!(documents.len(), 1);
        assert_eq!(
            documents[0].relative_path,
            PathBuf::from("nested/accepted.policy")
        );
    }

    #[test]
    fn generation_is_activated_only_after_bank_write() {
        let mut store = FakePolicyStore::new(0);
        let generation = commit_policy_generation(&mut store, &TranslatedPolicies::default())
            .expect("commit should succeed");

        assert_eq!(generation, 1);
        assert_eq!(store.generation, 1);
        assert_eq!(store.events, ["write-bank:16", "activate:1"]);
    }

    #[test]
    fn failed_bank_write_keeps_previous_generation_active() {
        let mut store = FakePolicyStore::new(4);
        store.fail_write = true;

        assert!(commit_policy_generation(&mut store, &TranslatedPolicies::default()).is_err());
        assert_eq!(store.generation, 4);
        assert_eq!(store.events, ["write-bank:16"]);
    }

    #[test]
    fn failed_activation_does_not_report_new_generation() {
        let mut store = FakePolicyStore::new(8);
        store.fail_activation = true;

        assert!(commit_policy_generation(&mut store, &TranslatedPolicies::default()).is_err());
        assert_eq!(store.generation, 8);
        assert_eq!(store.events, ["write-bank:16", "activate:9"]);
    }

    #[test]
    fn unchanged_and_repeatedly_failed_documents_are_not_retried() {
        let current = vec![static_policy("current")];
        let different = vec![static_policy("different")];

        assert!(!documents_need_sync(Some(&current), None, &current));
        assert!(!documents_need_sync(None, Some(&current), &current));
        assert!(documents_need_sync(Some(&different), None, &current));
    }

    #[test]
    fn preparing_bank_disables_entries_after_last_policy() {
        let prepared = prepare_array_bank(&[11_u32, 22], 0, "TEST").expect("prepare bank");

        assert_eq!(prepared.len(), POLICY_BANK_SIZE as usize);
        assert_eq!(&prepared[..3], &[11, 22, 0]);
        assert!(prepared[2..].iter().all(|entry| *entry == 0));
    }
}

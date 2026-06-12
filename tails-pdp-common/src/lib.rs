#![no_std]

#[cfg(any(feature = "user", test))]
extern crate std;

pub const COMMAND_LEN: usize = 16;
pub const RESOURCE_LEN: usize = 64;
pub const SOCKET_IP_LEN: usize = 16;
pub const ANY_SUBJECT: u32 = u32::MAX;

pub const MAX_POLICIES: u32 = 16;
pub const POLICY_BANK_COUNT: u32 = 2;
pub const POLICY_BANK_SIZE: u32 = MAX_POLICIES;
pub const POLICY_MAP_MAX_ENTRIES: u32 = POLICY_BANK_COUNT * POLICY_BANK_SIZE;
pub const POLICY_GENERATION_MAX_ENTRIES: u32 = 1;
pub const STREAM_ATTRIBUTE_MAX_ENTRIES: u32 = 1;
pub const ATTRIBUTE_BANK_COUNT: u32 = 2;
pub const ATTRIBUTE_MAP_MAX_ENTRIES: u32 = 1024;
pub const ATTRIBUTE_GENERATION_MAX_ENTRIES: u32 = 1;
pub const MAX_ATTRIBUTE_CONDITIONS: usize = 4;
pub const DEFCON_MIN_LEVEL: u32 = 1;
pub const DEFCON_MAX_LEVEL: u32 = 5;
pub const DEFAULT_DEFCON_LEVEL: u32 = DEFCON_MAX_LEVEL;

pub const FILE_OPEN_STATIC_POLICY_MAX_ENTRIES: u32 = POLICY_MAP_MAX_ENTRIES;
pub const FILE_OPEN_STREAM_POLICY_MAX_ENTRIES: u32 = POLICY_MAP_MAX_ENTRIES;
pub const SOCKET_BIND_STATIC_POLICY_MAX_ENTRIES: u32 = POLICY_MAP_MAX_ENTRIES;
pub const SOCKET_BIND_STREAM_POLICY_MAX_ENTRIES: u32 = POLICY_MAP_MAX_ENTRIES;

pub const fn policy_bank_offset(generation: u32) -> u32 {
    (generation % POLICY_BANK_COUNT) * POLICY_BANK_SIZE
}

pub const fn attribute_bank(generation: u32) -> u32 {
    generation % ATTRIBUTE_BANK_COUNT
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Entitlement {
    Permit = 0,
    Deny = 1,
}

impl Entitlement {
    pub const fn decision(self) -> i32 {
        match self {
            Self::Permit => 0,
            Self::Deny => 1,
        }
    }
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PolicyAction {
    FileOpen = 1,
    SocketBind = 2,
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum StreamAttribute {
    Time = 1,
    Hour = 2,
    Minute = 3,
    Second = 4,
    Defcon = 5,
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum StreamOperator {
    LessThan = 1,
    LessThanOrEqual = 2,
    Equal = 3,
    GreaterThanOrEqual = 4,
    GreaterThan = 5,
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SocketFamily {
    Any = 0,
    Inet = 2,
    Inet6 = 10,
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SocketTransport {
    Any = 0,
    Tcp = 1,
    Udp = 2,
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AttributeNamespace {
    System = 1,
    Subject = 2,
    Resource = 3,
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AttributeValueKind {
    Number = 1,
    String = 2,
    Bool = 3,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct AttributeHash {
    pub low: u64,
    pub high: u64,
}

impl AttributeHash {
    pub const fn zero() -> Self {
        Self { low: 0, high: 0 }
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct AttributeKey {
    pub bank: u32,
    pub namespace: u32,
    pub object_id_primary: u64,
    pub object_id_secondary: u64,
    pub name_hash: AttributeHash,
}

impl AttributeKey {
    pub const fn new(
        bank: u32,
        namespace: AttributeNamespace,
        object_id_primary: u64,
        object_id_secondary: u64,
        name_hash: AttributeHash,
    ) -> Self {
        Self {
            bank,
            namespace: namespace as u32,
            object_id_primary,
            object_id_secondary,
            name_hash,
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct AttributeValue {
    pub kind: AttributeValueKind,
    pub _pad: [u8; 7],
    pub number: u64,
    pub hash: AttributeHash,
}

impl AttributeValue {
    pub const fn number(value: u64) -> Self {
        Self {
            kind: AttributeValueKind::Number,
            _pad: [0; 7],
            number: value,
            hash: AttributeHash::zero(),
        }
    }

    pub const fn bool(value: bool) -> Self {
        Self {
            kind: AttributeValueKind::Bool,
            _pad: [0; 7],
            number: value as u64,
            hash: AttributeHash::zero(),
        }
    }

    pub const fn string(hash: AttributeHash) -> Self {
        Self {
            kind: AttributeValueKind::String,
            _pad: [0; 7],
            number: 0,
            hash,
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct AttributeCondition {
    pub namespace: AttributeNamespace,
    pub operator: StreamOperator,
    pub value_kind: AttributeValueKind,
    pub _pad: [u8; 5],
    pub name_hash: AttributeHash,
    pub value_number: u64,
    pub value_hash: AttributeHash,
}

impl AttributeCondition {
    pub const fn disabled() -> Self {
        Self {
            namespace: AttributeNamespace::System,
            operator: StreamOperator::Equal,
            value_kind: AttributeValueKind::Number,
            _pad: [0; 5],
            name_hash: AttributeHash::zero(),
            value_number: 0,
            value_hash: AttributeHash::zero(),
        }
    }
}

pub fn attribute_hash(value: &str) -> AttributeHash {
    attribute_hash_bytes(value.as_bytes())
}

pub fn attribute_hash_bytes(bytes: &[u8]) -> AttributeHash {
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut low = 0xcbf2_9ce4_8422_2325u64;
    let mut high = 0x6c62_272e_07bb_0142u64;
    let mut index = 0;

    while index < bytes.len() {
        let byte = bytes[index] as u64;
        low ^= byte;
        low = low.wrapping_mul(FNV_PRIME);
        high ^= byte.rotate_left((index % 8) as u32);
        high = high.wrapping_mul(FNV_PRIME);
        index += 1;
    }

    AttributeHash { low, high }
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Iso8601TimeParts {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
    pub _pad: u8,
}

impl Iso8601TimeParts {
    pub const fn new(year: u16, month: u8, day: u8, hour: u8, minute: u8, second: u8) -> Self {
        Self {
            year,
            month,
            day,
            hour,
            minute,
            second,
            _pad: 0,
        }
    }
}

fn fixed_name<const N: usize>(name: &str) -> [u8; N] {
    let mut value = [0; N];
    let bytes = name.as_bytes();
    let mut index = 0;

    while index < bytes.len() && index < N {
        value[index] = bytes[index];
        index += 1;
    }

    value
}

pub fn command_name(name: &str) -> [u8; COMMAND_LEN] {
    fixed_name(name)
}

pub fn resource_name(name: &str) -> [u8; RESOURCE_LEN] {
    fixed_name(name)
}

const fn bytes_are_zero<const N: usize>(value: &[u8; N]) -> bool {
    let mut index = 0;
    while index < N {
        if value[index] != 0 {
            return false;
        }
        index += 1;
    }
    true
}

#[cfg(feature = "user")]
fn fixed_string_len(bytes: &[u8]) -> usize {
    bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len())
}

#[cfg(feature = "user")]
pub fn encode_kernel_dev_t(device: u64) -> u64 {
    let major = libc::major(device) as u64;
    let minor = libc::minor(device) as u64;
    (major << 20) | minor
}

#[cfg(feature = "user")]
fn parse_socket_ip(resource: &[u8; RESOURCE_LEN]) -> std::io::Result<[u8; SOCKET_IP_LEN]> {
    use std::{io, net::IpAddr, str::FromStr};

    let len = fixed_string_len(resource);
    if len == 0 {
        return Ok([0; SOCKET_IP_LEN]);
    }

    let address = core::str::from_utf8(&resource[..len]).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            std::format!("socket address is not valid UTF-8: {error}"),
        )
    })?;
    match IpAddr::from_str(address).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            std::format!("invalid socket IP address '{address}': {error}"),
        )
    })? {
        IpAddr::V4(ip) => {
            let mut socket_ip = [0; SOCKET_IP_LEN];
            socket_ip[..4].copy_from_slice(&ip.octets());
            Ok(socket_ip)
        }
        IpAddr::V6(ip) => Ok(ip.octets()),
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct FileOpenStaticPolicy {
    pub entitlement: Entitlement,
    pub action: PolicyAction,
    pub enabled: u8,
    pub _pad: u8,
    pub subject: u32,
    pub command: [u8; COMMAND_LEN],
    pub resource: [u8; RESOURCE_LEN],
    pub resource_device: u64,
    pub resource_inode: u64,
}

impl FileOpenStaticPolicy {
    pub const fn disabled() -> Self {
        Self {
            entitlement: Entitlement::Permit,
            action: PolicyAction::FileOpen,
            enabled: 0,
            _pad: 0,
            subject: ANY_SUBJECT,
            command: [0; COMMAND_LEN],
            resource: [0; RESOURCE_LEN],
            resource_device: 0,
            resource_inode: 0,
        }
    }

    pub fn new(entitlement: Entitlement, subject: u32, command: &str, resource: &str) -> Self {
        Self {
            entitlement,
            action: PolicyAction::FileOpen,
            enabled: 1,
            _pad: 0,
            subject,
            command: command_name(command),
            resource: resource_name(resource),
            resource_device: 0,
            resource_inode: 0,
        }
    }

    pub const fn matches_any_resource(&self) -> bool {
        self.resource_device == 0 && self.resource_inode == 0
    }

    #[cfg(feature = "user")]
    pub fn resolve_resource_identity(mut self) -> std::io::Result<Self> {
        use std::{fs, io, os::unix::fs::MetadataExt, str};

        let len = fixed_string_len(&self.resource);
        if len == 0 {
            self.resource_device = 0;
            self.resource_inode = 0;
            return Ok(self);
        }

        let path = str::from_utf8(&self.resource[..len]).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                std::format!("resource path is not valid UTF-8: {error}"),
            )
        })?;
        let metadata = fs::metadata(path)?;
        self.resource_device = encode_kernel_dev_t(metadata.dev());
        self.resource_inode = metadata.ino();
        Ok(self)
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct FileOpenStreamPolicy {
    pub entitlement: Entitlement,
    pub action: PolicyAction,
    pub attribute: StreamAttribute,
    pub operator: StreamOperator,
    pub enabled: u8,
    pub stream_condition_enabled: u8,
    pub attribute_condition_count: u8,
    pub _pad: u8,
    pub subject: u32,
    pub command: [u8; COMMAND_LEN],
    pub resource: [u8; RESOURCE_LEN],
    pub resource_device: u64,
    pub resource_inode: u64,
    pub modulo: u64,
    pub value: u64,
    pub attribute_conditions: [AttributeCondition; MAX_ATTRIBUTE_CONDITIONS],
}

impl FileOpenStreamPolicy {
    pub const fn disabled() -> Self {
        Self {
            entitlement: Entitlement::Permit,
            action: PolicyAction::FileOpen,
            attribute: StreamAttribute::Time,
            operator: StreamOperator::LessThan,
            enabled: 0,
            stream_condition_enabled: 0,
            attribute_condition_count: 0,
            _pad: 0,
            subject: ANY_SUBJECT,
            command: [0; COMMAND_LEN],
            resource: [0; RESOURCE_LEN],
            resource_device: 0,
            resource_inode: 0,
            modulo: 0,
            value: 0,
            attribute_conditions: [AttributeCondition::disabled(); MAX_ATTRIBUTE_CONDITIONS],
        }
    }

    pub fn stream(entitlement: Entitlement, subject: u32, command: &str, resource: &str) -> Self {
        Self {
            entitlement,
            action: PolicyAction::FileOpen,
            attribute: StreamAttribute::Time,
            operator: StreamOperator::LessThan,
            enabled: 1,
            stream_condition_enabled: 0,
            attribute_condition_count: 0,
            _pad: 0,
            subject,
            command: command_name(command),
            resource: resource_name(resource),
            resource_device: 0,
            resource_inode: 0,
            modulo: 0,
            value: 0,
            attribute_conditions: [AttributeCondition::disabled(); MAX_ATTRIBUTE_CONDITIONS],
        }
    }

    pub fn time(
        entitlement: Entitlement,
        subject: u32,
        command: &str,
        resource: &str,
        operator: StreamOperator,
        modulo: u64,
        value: u64,
    ) -> Self {
        Self {
            entitlement,
            action: PolicyAction::FileOpen,
            attribute: StreamAttribute::Time,
            operator,
            enabled: 1,
            stream_condition_enabled: 1,
            attribute_condition_count: 0,
            _pad: 0,
            subject,
            command: command_name(command),
            resource: resource_name(resource),
            resource_device: 0,
            resource_inode: 0,
            modulo,
            value,
            attribute_conditions: [AttributeCondition::disabled(); MAX_ATTRIBUTE_CONDITIONS],
        }
    }

    pub const fn matches_any_resource(&self) -> bool {
        self.resource_device == 0 && self.resource_inode == 0
    }

    #[cfg(feature = "user")]
    pub fn resolve_resource_identity(mut self) -> std::io::Result<Self> {
        use std::{fs, io, os::unix::fs::MetadataExt, str};

        let len = fixed_string_len(&self.resource);
        if len == 0 {
            self.resource_device = 0;
            self.resource_inode = 0;
            return Ok(self);
        }

        let path = str::from_utf8(&self.resource[..len]).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                std::format!("resource path is not valid UTF-8: {error}"),
            )
        })?;
        let metadata = fs::metadata(path)?;
        self.resource_device = encode_kernel_dev_t(metadata.dev());
        self.resource_inode = metadata.ino();
        Ok(self)
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct SocketBindStaticPolicy {
    pub entitlement: Entitlement,
    pub action: PolicyAction,
    pub enabled: u8,
    pub socket_family: SocketFamily,
    pub socket_transport: SocketTransport,
    pub _pad: [u8; 3],
    pub subject: u32,
    pub command: [u8; COMMAND_LEN],
    pub socket_port: u16,
    pub _pad2: [u8; 6],
    pub resource: [u8; RESOURCE_LEN],
    pub socket_ip: [u8; SOCKET_IP_LEN],
}

impl SocketBindStaticPolicy {
    pub const fn disabled() -> Self {
        Self {
            entitlement: Entitlement::Permit,
            action: PolicyAction::SocketBind,
            enabled: 0,
            socket_family: SocketFamily::Any,
            socket_transport: SocketTransport::Any,
            _pad: [0; 3],
            subject: ANY_SUBJECT,
            command: [0; COMMAND_LEN],
            socket_port: 0,
            _pad2: [0; 6],
            resource: [0; RESOURCE_LEN],
            socket_ip: [0; SOCKET_IP_LEN],
        }
    }

    pub fn new(
        entitlement: Entitlement,
        subject: u32,
        command: &str,
        family: SocketFamily,
        transport: SocketTransport,
        port: u16,
        resource: &str,
    ) -> Self {
        Self {
            entitlement,
            action: PolicyAction::SocketBind,
            enabled: 1,
            socket_family: family,
            socket_transport: transport,
            _pad: [0; 3],
            subject,
            command: command_name(command),
            socket_port: port,
            _pad2: [0; 6],
            resource: resource_name(resource),
            socket_ip: [0; SOCKET_IP_LEN],
        }
    }

    pub const fn matches_any_socket_ip(&self) -> bool {
        bytes_are_zero(&self.socket_ip)
    }

    #[cfg(feature = "user")]
    pub fn resolve_resource_identity(mut self) -> std::io::Result<Self> {
        self.socket_ip = parse_socket_ip(&self.resource)?;
        Ok(self)
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct SocketBindStreamPolicy {
    pub entitlement: Entitlement,
    pub action: PolicyAction,
    pub attribute: StreamAttribute,
    pub operator: StreamOperator,
    pub enabled: u8,
    pub socket_family: SocketFamily,
    pub socket_transport: SocketTransport,
    pub stream_condition_enabled: u8,
    pub attribute_condition_count: u8,
    pub _pad: [u8; 7],
    pub subject: u32,
    pub command: [u8; COMMAND_LEN],
    pub socket_port: u16,
    pub _pad2: [u8; 6],
    pub resource: [u8; RESOURCE_LEN],
    pub socket_ip: [u8; SOCKET_IP_LEN],
    pub modulo: u64,
    pub value: u64,
    pub attribute_conditions: [AttributeCondition; MAX_ATTRIBUTE_CONDITIONS],
}

impl SocketBindStreamPolicy {
    pub const fn disabled() -> Self {
        Self {
            entitlement: Entitlement::Permit,
            action: PolicyAction::SocketBind,
            attribute: StreamAttribute::Time,
            operator: StreamOperator::LessThan,
            enabled: 0,
            socket_family: SocketFamily::Any,
            socket_transport: SocketTransport::Any,
            stream_condition_enabled: 0,
            attribute_condition_count: 0,
            _pad: [0; 7],
            subject: ANY_SUBJECT,
            command: [0; COMMAND_LEN],
            socket_port: 0,
            _pad2: [0; 6],
            resource: [0; RESOURCE_LEN],
            socket_ip: [0; SOCKET_IP_LEN],
            modulo: 0,
            value: 0,
            attribute_conditions: [AttributeCondition::disabled(); MAX_ATTRIBUTE_CONDITIONS],
        }
    }

    pub fn stream(
        entitlement: Entitlement,
        subject: u32,
        command: &str,
        family: SocketFamily,
        transport: SocketTransport,
        port: u16,
        resource: &str,
    ) -> Self {
        Self {
            entitlement,
            action: PolicyAction::SocketBind,
            attribute: StreamAttribute::Time,
            operator: StreamOperator::LessThan,
            enabled: 1,
            socket_family: family,
            socket_transport: transport,
            stream_condition_enabled: 0,
            attribute_condition_count: 0,
            _pad: [0; 7],
            subject,
            command: command_name(command),
            socket_port: port,
            _pad2: [0; 6],
            resource: resource_name(resource),
            socket_ip: [0; SOCKET_IP_LEN],
            modulo: 0,
            value: 0,
            attribute_conditions: [AttributeCondition::disabled(); MAX_ATTRIBUTE_CONDITIONS],
        }
    }

    pub fn time(
        entitlement: Entitlement,
        subject: u32,
        command: &str,
        family: SocketFamily,
        transport: SocketTransport,
        port: u16,
        resource: &str,
        operator: StreamOperator,
        modulo: u64,
        value: u64,
    ) -> Self {
        Self {
            entitlement,
            action: PolicyAction::SocketBind,
            attribute: StreamAttribute::Time,
            operator,
            enabled: 1,
            socket_family: family,
            socket_transport: transport,
            stream_condition_enabled: 1,
            attribute_condition_count: 0,
            _pad: [0; 7],
            subject,
            command: command_name(command),
            socket_port: port,
            _pad2: [0; 6],
            resource: resource_name(resource),
            socket_ip: [0; SOCKET_IP_LEN],
            modulo,
            value,
            attribute_conditions: [AttributeCondition::disabled(); MAX_ATTRIBUTE_CONDITIONS],
        }
    }

    pub const fn matches_any_socket_ip(&self) -> bool {
        bytes_are_zero(&self.socket_ip)
    }

    #[cfg(feature = "user")]
    pub fn resolve_resource_identity(mut self) -> std::io::Result<Self> {
        self.socket_ip = parse_socket_ip(&self.resource)?;
        Ok(self)
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct DecisionState {
    pub deny: u32,
    pub permit: u32,
    pub generation: u32,
}

impl DecisionState {
    pub const fn empty() -> Self {
        Self {
            deny: 0,
            permit: 0,
            generation: 0,
        }
    }

    pub const fn empty_for_generation(generation: u32) -> Self {
        Self {
            deny: 0,
            permit: 0,
            generation,
        }
    }

    pub fn record(&mut self, entitlement: Entitlement) {
        match entitlement {
            Entitlement::Deny => self.deny = 1,
            Entitlement::Permit => self.permit = 1,
        }
    }

    pub fn merge(&mut self, other: Self) {
        if other.deny != 0 {
            self.deny = 1;
        }
        if other.permit != 0 {
            self.permit = 1;
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct FileOpenRequest {
    pub subject: u32,
    pub command: [u8; COMMAND_LEN],
    pub resource_device: u64,
    pub resource_inode: u64,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct SocketBindRequest {
    pub subject: u32,
    pub command: [u8; COMMAND_LEN],
    pub socket_family: SocketFamily,
    pub socket_transport: SocketTransport,
    pub socket_port: u16,
    pub socket_ip: [u8; SOCKET_IP_LEN],
}

pub fn matches_stream_operator(operator: StreamOperator, left: u64, right: u64) -> bool {
    match operator {
        StreamOperator::LessThan => left < right,
        StreamOperator::LessThanOrEqual => left <= right,
        StreamOperator::Equal => left == right,
        StreamOperator::GreaterThanOrEqual => left >= right,
        StreamOperator::GreaterThan => left > right,
    }
}

fn matches_subject(policy_subject: u32, current_subject: u32) -> bool {
    policy_subject == ANY_SUBJECT || policy_subject == current_subject
}

fn matches_bytes<const N: usize>(policy_value: &[u8; N], current_value: &[u8; N]) -> bool {
    policy_value[0] == 0 || policy_value == current_value
}

fn matches_file_resource(
    policy_device: u64,
    policy_inode: u64,
    resource_device: u64,
    resource_inode: u64,
) -> bool {
    (policy_device == 0 && policy_inode == 0)
        || (policy_device == resource_device && policy_inode == resource_inode)
}

fn matches_socket_ip(
    policy_ip: &[u8; SOCKET_IP_LEN],
    current_family: SocketFamily,
    current_ip: &[u8; SOCKET_IP_LEN],
) -> bool {
    if bytes_are_zero(policy_ip) {
        return true;
    }

    match current_family {
        SocketFamily::Inet => policy_ip[..4] == current_ip[..4],
        SocketFamily::Inet6 => *policy_ip == *current_ip,
        SocketFamily::Any => false,
    }
}

fn matches_socket_resource(
    policy_family: SocketFamily,
    policy_transport: SocketTransport,
    policy_port: u16,
    policy_ip: &[u8; SOCKET_IP_LEN],
    request: &SocketBindRequest,
) -> bool {
    let family_matches =
        policy_family == SocketFamily::Any || policy_family == request.socket_family;
    let transport_matches =
        policy_transport == SocketTransport::Any || policy_transport == request.socket_transport;
    let port_matches = policy_port == 0 || policy_port == request.socket_port;

    family_matches
        && transport_matches
        && port_matches
        && matches_socket_ip(policy_ip, request.socket_family, &request.socket_ip)
}

struct StreamEvaluation {
    attribute: StreamAttribute,
    operator: StreamOperator,
    modulo: u64,
    value: u64,
    current_time: u64,
    current_iso8601_time: Iso8601TimeParts,
    current_defcon: u32,
}

fn evaluate_stream_condition(evaluation: &StreamEvaluation) -> Option<bool> {
    match evaluation.attribute {
        StreamAttribute::Time => {
            if evaluation.modulo == 0 {
                return None;
            }
            Some(matches_stream_operator(
                evaluation.operator,
                evaluation.current_time % evaluation.modulo,
                evaluation.value,
            ))
        }
        StreamAttribute::Hour => Some(matches_stream_operator(
            evaluation.operator,
            evaluation.current_iso8601_time.hour as u64,
            evaluation.value,
        )),
        StreamAttribute::Minute => Some(matches_stream_operator(
            evaluation.operator,
            evaluation.current_iso8601_time.minute as u64,
            evaluation.value,
        )),
        StreamAttribute::Second => Some(matches_stream_operator(
            evaluation.operator,
            evaluation.current_iso8601_time.second as u64,
            evaluation.value,
        )),
        StreamAttribute::Defcon => Some(matches_stream_operator(
            evaluation.operator,
            evaluation.current_defcon as u64,
            evaluation.value,
        )),
    }
}

fn stream_entitlement(
    entitlement: Entitlement,
    evaluation: &StreamEvaluation,
) -> Option<Entitlement> {
    if evaluate_stream_condition(evaluation)? {
        Some(entitlement)
    } else {
        None
    }
}

pub fn matches_attribute_condition(condition: &AttributeCondition, value: &AttributeValue) -> bool {
    if condition.value_kind != value.kind {
        return false;
    }

    match condition.value_kind {
        AttributeValueKind::Number => {
            matches_stream_operator(condition.operator, value.number, condition.value_number)
        }
        AttributeValueKind::Bool => {
            matches_stream_operator(condition.operator, value.number, condition.value_number)
        }
        AttributeValueKind::String => {
            condition.operator == StreamOperator::Equal && value.hash == condition.value_hash
        }
    }
}

pub const fn attribute_object_ids(
    namespace: AttributeNamespace,
    subject: u32,
    resource_device: u64,
    resource_inode: u64,
) -> (u64, u64) {
    match namespace {
        AttributeNamespace::System => (0, 0),
        AttributeNamespace::Subject => (subject as u64, 0),
        AttributeNamespace::Resource => (resource_device, resource_inode),
    }
}

pub fn evaluate_file_open_static_policy(
    request: &FileOpenRequest,
    policy: &FileOpenStaticPolicy,
) -> Option<Entitlement> {
    if policy.enabled == 0 || policy.action != PolicyAction::FileOpen {
        return None;
    }
    if !matches_subject(policy.subject, request.subject) {
        return None;
    }
    if !matches_bytes(&policy.command, &request.command) {
        return None;
    }
    if !matches_file_resource(
        policy.resource_device,
        policy.resource_inode,
        request.resource_device,
        request.resource_inode,
    ) {
        return None;
    }
    Some(policy.entitlement)
}

pub fn file_open_stream_policy_applies_to_request(
    request: &FileOpenRequest,
    policy: &FileOpenStreamPolicy,
) -> bool {
    if policy.enabled == 0 || policy.action != PolicyAction::FileOpen {
        return false;
    }
    if !matches_subject(policy.subject, request.subject) {
        return false;
    }
    if !matches_bytes(&policy.command, &request.command) {
        return false;
    }
    if !matches_file_resource(
        policy.resource_device,
        policy.resource_inode,
        request.resource_device,
        request.resource_inode,
    ) {
        return false;
    }
    true
}

pub fn file_open_stream_legacy_entitlement(
    current_time: u64,
    current_iso8601_time: Iso8601TimeParts,
    current_defcon: u32,
    policy: &FileOpenStreamPolicy,
) -> Option<Entitlement> {
    if policy.stream_condition_enabled == 0 {
        return Some(policy.entitlement);
    }

    let evaluation = StreamEvaluation {
        attribute: policy.attribute,
        operator: policy.operator,
        modulo: policy.modulo,
        value: policy.value,
        current_time,
        current_iso8601_time,
        current_defcon,
    };
    stream_entitlement(policy.entitlement, &evaluation)
}

pub fn evaluate_file_open_stream_policy(
    request: &FileOpenRequest,
    current_time: u64,
    current_iso8601_time: Iso8601TimeParts,
    current_defcon: u32,
    policy: &FileOpenStreamPolicy,
) -> Option<Entitlement> {
    if !file_open_stream_policy_applies_to_request(request, policy) {
        return None;
    }
    if policy.attribute_condition_count != 0 {
        return None;
    }
    file_open_stream_legacy_entitlement(current_time, current_iso8601_time, current_defcon, policy)
}

pub fn evaluate_socket_bind_static_policy(
    request: &SocketBindRequest,
    policy: &SocketBindStaticPolicy,
) -> Option<Entitlement> {
    if policy.enabled == 0 || policy.action != PolicyAction::SocketBind {
        return None;
    }
    if !matches_subject(policy.subject, request.subject) {
        return None;
    }
    if !matches_bytes(&policy.command, &request.command) {
        return None;
    }
    if !matches_socket_resource(
        policy.socket_family,
        policy.socket_transport,
        policy.socket_port,
        &policy.socket_ip,
        request,
    ) {
        return None;
    }
    Some(policy.entitlement)
}

pub fn socket_bind_stream_policy_applies_to_request(
    request: &SocketBindRequest,
    policy: &SocketBindStreamPolicy,
) -> bool {
    if policy.enabled == 0 || policy.action != PolicyAction::SocketBind {
        return false;
    }
    if !matches_subject(policy.subject, request.subject) {
        return false;
    }
    if !matches_bytes(&policy.command, &request.command) {
        return false;
    }
    if !matches_socket_resource(
        policy.socket_family,
        policy.socket_transport,
        policy.socket_port,
        &policy.socket_ip,
        request,
    ) {
        return false;
    }
    true
}

pub fn socket_bind_stream_legacy_entitlement(
    current_time: u64,
    current_iso8601_time: Iso8601TimeParts,
    current_defcon: u32,
    policy: &SocketBindStreamPolicy,
) -> Option<Entitlement> {
    if policy.stream_condition_enabled == 0 {
        return Some(policy.entitlement);
    }

    let evaluation = StreamEvaluation {
        attribute: policy.attribute,
        operator: policy.operator,
        modulo: policy.modulo,
        value: policy.value,
        current_time,
        current_iso8601_time,
        current_defcon,
    };
    stream_entitlement(policy.entitlement, &evaluation)
}

pub fn evaluate_socket_bind_stream_policy(
    request: &SocketBindRequest,
    current_time: u64,
    current_iso8601_time: Iso8601TimeParts,
    current_defcon: u32,
    policy: &SocketBindStreamPolicy,
) -> Option<Entitlement> {
    if !socket_bind_stream_policy_applies_to_request(request, policy) {
        return None;
    }
    if policy.attribute_condition_count != 0 {
        return None;
    }
    socket_bind_stream_legacy_entitlement(
        current_time,
        current_iso8601_time,
        current_defcon,
        policy,
    )
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for AttributeHash {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for AttributeKey {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for AttributeValue {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for AttributeCondition {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FileOpenStaticPolicy {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FileOpenStreamPolicy {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for SocketBindStaticPolicy {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for SocketBindStreamPolicy {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Iso8601TimeParts {}

#[cfg(test)]
mod tests {
    use super::*;

    fn file_open_request() -> FileOpenRequest {
        FileOpenRequest {
            subject: 1000,
            command: command_name("cat"),
            resource_device: 0,
            resource_inode: 0,
        }
    }

    fn socket_bind_request() -> SocketBindRequest {
        SocketBindRequest {
            subject: 1000,
            command: command_name("python3"),
            socket_family: SocketFamily::Inet,
            socket_transport: SocketTransport::Tcp,
            socket_port: 8080,
            socket_ip: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        }
    }

    fn attribute_condition(
        value_kind: AttributeValueKind,
        operator: StreamOperator,
        value_number: u64,
        value_hash: AttributeHash,
    ) -> AttributeCondition {
        AttributeCondition {
            namespace: AttributeNamespace::Subject,
            operator,
            value_kind,
            _pad: [0; 5],
            name_hash: attribute_hash("position"),
            value_number,
            value_hash,
        }
    }

    #[test]
    fn attribute_conditions_match_numbers_and_booleans() {
        let number_condition = attribute_condition(
            AttributeValueKind::Number,
            StreamOperator::LessThanOrEqual,
            3,
            AttributeHash::zero(),
        );
        let bool_condition = attribute_condition(
            AttributeValueKind::Bool,
            StreamOperator::Equal,
            1,
            AttributeHash::zero(),
        );

        assert!(matches_attribute_condition(
            &number_condition,
            &AttributeValue::number(2)
        ));
        assert!(!matches_attribute_condition(
            &number_condition,
            &AttributeValue::number(4)
        ));
        assert!(matches_attribute_condition(
            &bool_condition,
            &AttributeValue::bool(true)
        ));
        assert!(!matches_attribute_condition(
            &bool_condition,
            &AttributeValue::bool(false)
        ));
    }

    #[test]
    fn attribute_conditions_match_string_hashes_only_by_equality() {
        let condition = attribute_condition(
            AttributeValueKind::String,
            StreamOperator::Equal,
            0,
            attribute_hash("engineer"),
        );
        let unsupported_operator = attribute_condition(
            AttributeValueKind::String,
            StreamOperator::GreaterThan,
            0,
            attribute_hash("engineer"),
        );

        assert!(matches_attribute_condition(
            &condition,
            &AttributeValue::string(attribute_hash("engineer"))
        ));
        assert!(!matches_attribute_condition(
            &condition,
            &AttributeValue::string(attribute_hash("manager"))
        ));
        assert!(!matches_attribute_condition(
            &unsupported_operator,
            &AttributeValue::string(attribute_hash("engineer"))
        ));
    }

    #[test]
    fn attribute_conditions_reject_type_mismatches() {
        let condition = attribute_condition(
            AttributeValueKind::Number,
            StreamOperator::Equal,
            3,
            AttributeHash::zero(),
        );

        assert!(!matches_attribute_condition(
            &condition,
            &AttributeValue::string(attribute_hash("3"))
        ));
    }

    #[test]
    fn attribute_object_ids_are_namespace_scoped() {
        assert_eq!(
            attribute_object_ids(AttributeNamespace::System, 1000, 42, 99),
            (0, 0)
        );
        assert_eq!(
            attribute_object_ids(AttributeNamespace::Subject, 1000, 42, 99),
            (1000, 0)
        );
        assert_eq!(
            attribute_object_ids(AttributeNamespace::Resource, 1000, 42, 99),
            (42, 99)
        );
    }

    #[test]
    fn stream_policy_with_dynamic_attributes_requires_map_lookup() {
        let mut policy = FileOpenStreamPolicy::stream(Entitlement::Deny, 1000, "", "");
        policy.attribute_condition_count = 1;
        policy.attribute_conditions[0] = attribute_condition(
            AttributeValueKind::String,
            StreamOperator::Equal,
            0,
            attribute_hash("engineer"),
        );

        let result = evaluate_file_open_stream_policy(
            &file_open_request(),
            0,
            Iso8601TimeParts::new(2026, 5, 9, 12, 0, 0),
            DEFAULT_DEFCON_LEVEL,
            &policy,
        );

        assert_eq!(result, None);
    }

    #[test]
    fn stream_policy_returns_entitlement_when_condition_matches() {
        let policy = FileOpenStreamPolicy::time(
            Entitlement::Deny,
            1000,
            "",
            "",
            StreamOperator::LessThan,
            10,
            5,
        );

        let result = evaluate_file_open_stream_policy(
            &file_open_request(),
            3,
            Iso8601TimeParts::new(2026, 5, 9, 12, 0, 0),
            DEFAULT_DEFCON_LEVEL,
            &policy,
        );

        assert_eq!(result, Some(Entitlement::Deny));
    }

    #[test]
    fn stream_policy_is_not_applicable_when_condition_does_not_match() {
        let policy = FileOpenStreamPolicy::time(
            Entitlement::Deny,
            1000,
            "",
            "",
            StreamOperator::LessThan,
            10,
            5,
        );

        let result = evaluate_file_open_stream_policy(
            &file_open_request(),
            8,
            Iso8601TimeParts::new(2026, 5, 9, 12, 0, 0),
            DEFAULT_DEFCON_LEVEL,
            &policy,
        );

        assert_eq!(result, None);
    }

    #[test]
    fn stream_policy_with_zero_modulo_is_not_applicable() {
        let policy = FileOpenStreamPolicy::time(
            Entitlement::Permit,
            1000,
            "",
            "",
            StreamOperator::LessThan,
            0,
            5,
        );

        let result = evaluate_file_open_stream_policy(
            &file_open_request(),
            3,
            Iso8601TimeParts::new(2026, 5, 9, 12, 0, 0),
            DEFAULT_DEFCON_LEVEL,
            &policy,
        );

        assert_eq!(result, None);
    }

    #[test]
    fn defcon_stream_policy_returns_entitlement_when_condition_matches() {
        let mut policy = FileOpenStreamPolicy::time(
            Entitlement::Deny,
            1000,
            "",
            "",
            StreamOperator::LessThanOrEqual,
            0,
            2,
        );
        policy.attribute = StreamAttribute::Defcon;

        let result = evaluate_file_open_stream_policy(
            &file_open_request(),
            0,
            Iso8601TimeParts::new(2026, 5, 9, 12, 0, 0),
            2,
            &policy,
        );

        assert_eq!(result, Some(Entitlement::Deny));
    }

    #[test]
    fn defcon_stream_policy_is_not_applicable_when_condition_does_not_match() {
        let mut policy = FileOpenStreamPolicy::time(
            Entitlement::Deny,
            1000,
            "",
            "",
            StreamOperator::LessThanOrEqual,
            0,
            2,
        );
        policy.attribute = StreamAttribute::Defcon;

        let result = evaluate_file_open_stream_policy(
            &file_open_request(),
            0,
            Iso8601TimeParts::new(2026, 5, 9, 12, 0, 0),
            3,
            &policy,
        );

        assert_eq!(result, None);
    }

    #[test]
    fn file_open_stream_policy_respects_command_filter() {
        let mut policy = FileOpenStreamPolicy::time(
            Entitlement::Deny,
            1000,
            "cat",
            "",
            StreamOperator::LessThanOrEqual,
            0,
            2,
        );
        policy.attribute = StreamAttribute::Defcon;

        let denied = evaluate_file_open_stream_policy(
            &file_open_request(),
            0,
            Iso8601TimeParts::new(2026, 5, 9, 12, 0, 0),
            2,
            &policy,
        );

        let allowed_request = FileOpenRequest {
            command: command_name("tail"),
            ..file_open_request()
        };
        let not_applicable = evaluate_file_open_stream_policy(
            &allowed_request,
            0,
            Iso8601TimeParts::new(2026, 5, 9, 12, 0, 0),
            2,
            &policy,
        );

        assert_eq!(denied, Some(Entitlement::Deny));
        assert_eq!(not_applicable, None);
    }

    #[test]
    fn socket_bind_stream_policy_respects_command_filter() {
        let mut policy = SocketBindStreamPolicy::time(
            Entitlement::Deny,
            1000,
            "python3",
            SocketFamily::Inet,
            SocketTransport::Tcp,
            8080,
            "0.0.0.0",
            StreamOperator::LessThanOrEqual,
            0,
            2,
        );
        policy.attribute = StreamAttribute::Defcon;

        let denied = evaluate_socket_bind_stream_policy(
            &socket_bind_request(),
            0,
            Iso8601TimeParts::new(2026, 5, 9, 12, 0, 0),
            2,
            &policy,
        );

        let different_command_request = SocketBindRequest {
            command: command_name("nc"),
            ..socket_bind_request()
        };
        let not_applicable = evaluate_socket_bind_stream_policy(
            &different_command_request,
            0,
            Iso8601TimeParts::new(2026, 5, 9, 12, 0, 0),
            2,
            &policy,
        );

        assert_eq!(denied, Some(Entitlement::Deny));
        assert_eq!(not_applicable, None);
    }
}

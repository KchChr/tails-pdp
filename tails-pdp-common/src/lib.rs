#![no_std]

#[cfg(feature = "user")]
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

pub const FILE_OPEN_STATIC_POLICY_MAX_ENTRIES: u32 = POLICY_MAP_MAX_ENTRIES;
pub const FILE_OPEN_STREAM_POLICY_MAX_ENTRIES: u32 = POLICY_MAP_MAX_ENTRIES;
pub const SOCKET_BIND_STATIC_POLICY_MAX_ENTRIES: u32 = POLICY_MAP_MAX_ENTRIES;
pub const SOCKET_BIND_STREAM_POLICY_MAX_ENTRIES: u32 = POLICY_MAP_MAX_ENTRIES;

pub const fn policy_bank_offset(generation: u32) -> u32 {
    (generation % POLICY_BANK_COUNT) * POLICY_BANK_SIZE
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

    pub const fn inverse(self) -> Self {
        match self {
            Self::Permit => Self::Deny,
            Self::Deny => Self::Permit,
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
fn encode_kernel_dev_t(device: u64) -> u64 {
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
    pub _pad: [u8; 3],
    pub subject: u32,
    pub resource: [u8; RESOURCE_LEN],
    pub resource_device: u64,
    pub resource_inode: u64,
    pub modulo: u64,
    pub value: u64,
}

impl FileOpenStreamPolicy {
    pub const fn disabled() -> Self {
        Self {
            entitlement: Entitlement::Permit,
            action: PolicyAction::FileOpen,
            attribute: StreamAttribute::Time,
            operator: StreamOperator::LessThan,
            enabled: 0,
            _pad: [0; 3],
            subject: ANY_SUBJECT,
            resource: [0; RESOURCE_LEN],
            resource_device: 0,
            resource_inode: 0,
            modulo: 0,
            value: 0,
        }
    }

    pub fn time(
        entitlement: Entitlement,
        subject: u32,
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
            _pad: [0; 3],
            subject,
            resource: resource_name(resource),
            resource_device: 0,
            resource_inode: 0,
            modulo,
            value,
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
            socket_port: 0,
            _pad2: [0; 6],
            resource: [0; RESOURCE_LEN],
            socket_ip: [0; SOCKET_IP_LEN],
        }
    }

    pub fn new(
        entitlement: Entitlement,
        subject: u32,
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
    pub _pad: u8,
    pub subject: u32,
    pub socket_port: u16,
    pub _pad2: [u8; 6],
    pub resource: [u8; RESOURCE_LEN],
    pub socket_ip: [u8; SOCKET_IP_LEN],
    pub modulo: u64,
    pub value: u64,
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
            _pad: 0,
            subject: ANY_SUBJECT,
            socket_port: 0,
            _pad2: [0; 6],
            resource: [0; RESOURCE_LEN],
            socket_ip: [0; SOCKET_IP_LEN],
            modulo: 0,
            value: 0,
        }
    }

    pub fn time(
        entitlement: Entitlement,
        subject: u32,
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
            _pad: 0,
            subject,
            socket_port: port,
            _pad2: [0; 6],
            resource: resource_name(resource),
            socket_ip: [0; SOCKET_IP_LEN],
            modulo,
            value,
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
    }
}

fn stream_entitlement(
    entitlement: Entitlement,
    evaluation: &StreamEvaluation,
) -> Option<Entitlement> {
    let condition = evaluate_stream_condition(evaluation)?;

    Some(if condition {
        entitlement
    } else {
        entitlement.inverse()
    })
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

pub fn evaluate_file_open_stream_policy(
    request: &FileOpenRequest,
    current_time: u64,
    current_iso8601_time: Iso8601TimeParts,
    policy: &FileOpenStreamPolicy,
) -> Option<Entitlement> {
    if policy.enabled == 0 || policy.action != PolicyAction::FileOpen {
        return None;
    }
    if !matches_subject(policy.subject, request.subject) {
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

    let evaluation = StreamEvaluation {
        attribute: policy.attribute,
        operator: policy.operator,
        modulo: policy.modulo,
        value: policy.value,
        current_time,
        current_iso8601_time,
    };
    stream_entitlement(policy.entitlement, &evaluation)
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

pub fn evaluate_socket_bind_stream_policy(
    request: &SocketBindRequest,
    current_time: u64,
    current_iso8601_time: Iso8601TimeParts,
    policy: &SocketBindStreamPolicy,
) -> Option<Entitlement> {
    if policy.enabled == 0 || policy.action != PolicyAction::SocketBind {
        return None;
    }
    if !matches_subject(policy.subject, request.subject) {
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

    let evaluation = StreamEvaluation {
        attribute: policy.attribute,
        operator: policy.operator,
        modulo: policy.modulo,
        value: policy.value,
        current_time,
        current_iso8601_time,
    };
    stream_entitlement(policy.entitlement, &evaluation)
}

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

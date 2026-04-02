#![no_std]

#[cfg(feature = "user")]
extern crate std;

pub const COMMAND_LEN: usize = 16;
pub const RESOURCE_LEN: usize = 64;
pub const ANY_SUBJECT: u32 = u32::MAX;
pub const POLICY_HOOK_COUNT: u32 = 2;
pub const STATIC_POLICY_SLOTS_PER_HOOK: u32 = 64;
pub const STREAM_POLICY_SLOTS_PER_HOOK: u32 = 64;

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
    TaskSetNice = 2,
}

impl PolicyAction {
    pub const fn hook_slot(self) -> u32 {
        match self {
            Self::FileOpen => 0,
            Self::TaskSetNice => 1,
        }
    }

    pub const fn segment_start(self, slots_per_hook: u32) -> u32 {
        self.hook_slot() * slots_per_hook
    }

    pub const fn segment_end(self, slots_per_hook: u32) -> u32 {
        self.segment_start(slots_per_hook) + slots_per_hook
    }

    pub const fn local_slot(self, local_index: u32, slots_per_hook: u32) -> u32 {
        self.segment_start(slots_per_hook) + local_index
    }
}

pub const POLICY_HOOKS: [PolicyAction; POLICY_HOOK_COUNT as usize] =
    [PolicyAction::FileOpen, PolicyAction::TaskSetNice];

#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum StreamAttribute {
    Time = 1,
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

fn fixed_name<const N: usize>(name: &str) -> [u8; N] {
    let mut value = [0; N];
    let bytes = name.as_bytes();
    let mut i = 0;

    while i < bytes.len() && i < N {
        value[i] = bytes[i];
        i += 1;
    }

    value
}

pub fn command_name(name: &str) -> [u8; COMMAND_LEN] {
    fixed_name(name)
}

pub fn resource_name(name: &str) -> [u8; RESOURCE_LEN] {
    fixed_name(name)
}

#[cfg(feature = "user")]
fn fixed_string_len(bytes: &[u8]) -> usize {
    bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len())
}

#[cfg(feature = "user")]
fn encode_kernel_dev_t(device: u64) -> u64 {
    let major = libc::major(device) as u64;
    let minor = libc::minor(device) as u64;
    (major << 20) | minor
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct StaticPolicy {
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

impl StaticPolicy {
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

    pub fn new(
        entitlement: Entitlement,
        subject: u32,
        action: PolicyAction,
        command: &str,
        resource: &str,
    ) -> Self {
        Self {
            entitlement,
            action,
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
pub struct StreamPolicy {
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

impl StreamPolicy {
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
        action: PolicyAction,
        resource: &str,
        operator: StreamOperator,
        modulo: u64,
        value: u64,
    ) -> Self {
        Self {
            entitlement,
            action,
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

#[cfg(feature = "user")]
unsafe impl aya::Pod for StaticPolicy {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for StreamPolicy {}

#[cfg(test)]
mod tests {
    use super::{COMMAND_LEN, RESOURCE_LEN, command_name, resource_name};

    #[test]
    fn command_name_zero_pads_short_names() {
        let command = command_name("systemd");

        assert_eq!(&command[..8], b"systemd\0");
        assert_eq!(command.len(), COMMAND_LEN);
        assert!(command[8..].iter().all(|b| *b == 0));
    }

    #[test]
    fn command_name_truncates_long_names() {
        let command = command_name("1234567890abcdefgh");

        assert_eq!(command, *b"1234567890abcdef");
    }

    #[test]
    fn resource_name_zero_pads_short_names() {
        let resource = resource_name("shadow");

        assert_eq!(&resource[..7], b"shadow\0");
        assert_eq!(resource.len(), RESOURCE_LEN);
        assert!(resource[7..].iter().all(|b| *b == 0));
    }
}

#![no_std]

pub const COMMAND_LEN: usize = 16;
pub const RESOURCE_LEN: usize = 64;
pub const ANY_SUBJECT: u32 = u32::MAX;

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
    TaskSetNice = 2,
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
        }
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for StaticPolicy {}

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

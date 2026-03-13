#![no_std]

pub const COMMAND_LEN: usize = 16;

#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Action {
    FileOpen = 1,
    TaskSetNice = 2,
}

impl Action {
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

impl From<Action> for u8 {
    fn from(value: Action) -> Self {
        value as u8
    }
}

pub fn command_name(name: &str) -> [u8; COMMAND_LEN] {
    let mut command = [0; COMMAND_LEN];
    let bytes = name.as_bytes();
    let mut i = 0;

    while i < bytes.len() && i < COMMAND_LEN {
        command[i] = bytes[i];
        i += 1;
    }

    command
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct AuthorizationSubscription {
    pub subject_uid: u32,
    pub subject_gid: u32,
    pub action: u8,
    pub _pad: [u8; 3],
    pub pid: u32,
    pub tgid: u32,
    pub resource_id: u64,
    pub command: [u8; COMMAND_LEN],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for AuthorizationSubscription {}

#[cfg(test)]
mod tests {
    use super::{COMMAND_LEN, command_name};

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
}

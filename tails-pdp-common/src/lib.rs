#![no_std]

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
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for AuthorizationSubscription {}

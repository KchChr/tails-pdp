#![no_std]

pub const ACTION_FILE_OPEN: u8 = 1;

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

pub const ACT_LEN: usize = 32;
pub const RES_LEN: usize = 128;

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct AuthorizationSubscription {
    pub subject: u32,
    pub action: [u8; ACT_LEN],
    pub resource: [u8; RES_LEN],
    pub action_hash: u64,
    pub resource_hash: u64,
}

impl AuthorizationSubscription {
    #[inline(always)]
    pub fn new(subject: u32, action_bytes: &[u8], resource_bytes: &[u8]) -> Self {
        let mut this = Self {
            subject,
            action: [0; ACT_LEN],
            resource: [0; RES_LEN],
            action_hash: 0,
            resource_hash: 0,
        };

        let action_len = core::cmp::min(action_bytes.len(), ACT_LEN.saturating_sub(1));
        if action_len > 0 {
            unsafe {
                core::ptr::copy_nonoverlapping(
                    action_bytes.as_ptr(),
                    this.action.as_mut_ptr(),
                    action_len,
                );
            }
        }

        let resource_len = core::cmp::min(resource_bytes.len(), RES_LEN.saturating_sub(1));
        if resource_len > 0 {
            unsafe {
                core::ptr::copy_nonoverlapping(
                    resource_bytes.as_ptr(),
                    this.resource.as_mut_ptr(),
                    resource_len,
                );
            }
        }

        this.action_hash = fnv1a_hash_cstr_fixed(&this.action);
        this.resource_hash = fnv1a_hash_cstr_fixed(&this.resource);
        this
    }

    #[inline(always)]
    pub fn new_file_open(subject: u32, resource_bytes: &[u8]) -> Self {
        Self::new(subject, b"file_open", resource_bytes)
    }
}

#[inline(always)]
fn fnv1a_hash_cstr_fixed<const N: usize>(bytes: &[u8; N]) -> u64 {
    const OFFSET_BASIS: u64 = 0xcbf29ce484222325;
    const PRIME: u64 = 0x100000001b3;

    let mut hash = OFFSET_BASIS;
    let mut i = 0;
    while i < N {
        let b = bytes[i];
        if b == 0 {
            break;
        }
        hash ^= b as u64;
        hash = hash.wrapping_mul(PRIME);
        i += 1;
    }

    hash
}

use core::ptr::addr_of;

use aya_ebpf::{helpers::bpf_probe_read_kernel, programs::LsmContext};

use crate::vmlinux;

#[derive(Copy, Clone)]
pub(crate) struct FileOpenResource {
    pub device: u64,
    pub inode: u64,
}

/// Reads the stable file identity used by policy matching.
///
/// A failed kernel read is kept distinct from the valid wildcard identity `(0, 0)` so callers can
/// fail closed instead of accidentally matching a wildcard policy.
pub(crate) fn read_file_open_resource(ctx: &LsmContext) -> Option<FileOpenResource> {
    let file_ptr: *const vmlinux::file = ctx.arg(0);
    if file_ptr.is_null() {
        return None;
    }

    // SAFETY: `file_ptr` is supplied by the `file_open` LSM hook. The helper performs a checked
    // kernel-memory read; no borrowed reference is created from the raw pointer.
    let Ok(inode_ptr) = (unsafe { bpf_probe_read_kernel(addr_of!((*file_ptr).f_inode)) }) else {
        return None;
    };
    if inode_ptr.is_null() {
        return None;
    }

    // SAFETY: `inode_ptr` was obtained through the checked helper above and is read only through
    // `bpf_probe_read_kernel`.
    let Ok(sb_ptr) = (unsafe { bpf_probe_read_kernel(addr_of!((*inode_ptr).i_sb)) }) else {
        return None;
    };
    if sb_ptr.is_null() {
        return None;
    }

    // SAFETY: `sb_ptr` was obtained through a checked kernel-memory read.
    let Ok(device) = (unsafe { bpf_probe_read_kernel(addr_of!((*sb_ptr).s_dev)) }) else {
        return None;
    };
    // SAFETY: `inode_ptr` was obtained through a checked kernel-memory read.
    let Ok(inode) = (unsafe { bpf_probe_read_kernel(addr_of!((*inode_ptr).i_ino)) }) else {
        return None;
    };

    Some(FileOpenResource {
        device: device as u64,
        inode,
    })
}

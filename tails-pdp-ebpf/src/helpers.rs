use core::ptr::addr_of;

use aya_ebpf::{helpers::bpf_probe_read_kernel, programs::LsmContext};

use crate::vmlinux;

#[derive(Copy, Clone)]
pub(crate) struct FileOpenResource {
    pub device: u64,
    pub inode: u64,
}

impl FileOpenResource {
    pub const fn empty() -> Self {
        Self {
            device: 0,
            inode: 0,
        }
    }
}

pub(crate) fn read_file_open_resource(ctx: &LsmContext) -> FileOpenResource {
    let file_ptr: *const vmlinux::file = ctx.arg(0);
    if file_ptr.is_null() {
        return FileOpenResource::empty();
    }

    let Ok(inode_ptr) = (unsafe { bpf_probe_read_kernel(addr_of!((*file_ptr).f_inode)) }) else {
        return FileOpenResource::empty();
    };
    if inode_ptr.is_null() {
        return FileOpenResource::empty();
    }

    let Ok(sb_ptr) = (unsafe { bpf_probe_read_kernel(addr_of!((*inode_ptr).i_sb)) }) else {
        return FileOpenResource::empty();
    };
    if sb_ptr.is_null() {
        return FileOpenResource::empty();
    }

    let Ok(device) = (unsafe { bpf_probe_read_kernel(addr_of!((*sb_ptr).s_dev)) }) else {
        return FileOpenResource::empty();
    };
    let Ok(inode) = (unsafe { bpf_probe_read_kernel(addr_of!((*inode_ptr).i_ino)) }) else {
        return FileOpenResource::empty();
    };

    FileOpenResource {
        device: device as u64,
        inode,
    }
}

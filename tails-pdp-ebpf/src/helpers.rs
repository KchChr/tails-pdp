use core::ptr::addr_of;

use aya_ebpf::{helpers::bpf_probe_read_kernel, programs::LsmContext};

use crate::vmlinux;

pub(crate) fn read_file_open_resource_identity(ctx: &LsmContext) -> (u64, u64) {
    let file_ptr: *const vmlinux::file = ctx.arg(0);
    if file_ptr.is_null() {
        return (0, 0);
    }

    let Ok(inode_ptr) = (unsafe { bpf_probe_read_kernel(addr_of!((*file_ptr).f_inode)) }) else {
        return (0, 0);
    };
    if inode_ptr.is_null() {
        return (0, 0);
    }

    let Ok(sb_ptr) = (unsafe { bpf_probe_read_kernel(addr_of!((*inode_ptr).i_sb)) }) else {
        return (0, 0);
    };
    if sb_ptr.is_null() {
        return (0, 0);
    }

    let Ok(device) = (unsafe { bpf_probe_read_kernel(addr_of!((*sb_ptr).s_dev)) }) else {
        return (0, 0);
    };
    let Ok(inode) = (unsafe { bpf_probe_read_kernel(addr_of!((*inode_ptr).i_ino)) }) else {
        return (0, 0);
    };

    (device as u64, inode)
}

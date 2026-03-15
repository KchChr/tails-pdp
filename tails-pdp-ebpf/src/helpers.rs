use core::ptr::addr_of;

use aya_ebpf::{
    helpers::{bpf_probe_read_kernel, bpf_probe_read_kernel_str_bytes},
    programs::LsmContext,
};
use tails_pdp_common::RESOURCE_LEN;

use crate::vmlinux;

pub(crate) fn read_file_open_resource(ctx: &LsmContext) -> [u8; RESOURCE_LEN] {
    let mut resource = [0; RESOURCE_LEN];
    let file_ptr: *const vmlinux::file = ctx.arg(0);
    if file_ptr.is_null() {
        return resource;
    }

    let Ok(dentry_ptr) = (unsafe { bpf_probe_read_kernel(addr_of!((*file_ptr).f_path.dentry)) })
    else {
        return resource;
    };
    if dentry_ptr.is_null() {
        return resource;
    }

    let Ok(name_ptr) = (unsafe { bpf_probe_read_kernel(addr_of!((*dentry_ptr).d_name.name)) })
    else {
        return resource;
    };
    if name_ptr.is_null() {
        return resource;
    }

    let _ = unsafe { bpf_probe_read_kernel_str_bytes(name_ptr.cast(), &mut resource) };
    resource
}

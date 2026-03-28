use core::ptr::addr_of;

use aya_ebpf::{helpers::generated::bpf_d_path, programs::LsmContext};
use tails_pdp_common::RESOURCE_LEN;

use crate::vmlinux;

pub(crate) fn read_file_open_resource(ctx: &LsmContext) -> [u8; RESOURCE_LEN] {
    let mut resource = [0; RESOURCE_LEN];
    let file_ptr: *const vmlinux::file = ctx.arg(0);
    if file_ptr.is_null() {
        return resource;
    }

    let path_ptr = unsafe { addr_of!((*file_ptr).f_path) as *mut vmlinux::path };
    let _ = unsafe {
        bpf_d_path(
            path_ptr.cast(),
            resource.as_mut_ptr().cast(),
            RESOURCE_LEN as u32,
        )
    };
    resource
}

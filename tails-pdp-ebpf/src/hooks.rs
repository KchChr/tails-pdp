use aya_ebpf::{EbpfContext, macros::lsm, programs::LsmContext};

use crate::{
    helpers::read_socket_bind_resource,
    maps::{CURRENT_TIME, POLICY_JUMP_TABLE, TAIL_IDX_FILE_OPEN_STATIC},
    policies::{
        socket_bind_static_policies::evaluate_policies as evaluate_socket_bind_static_policies,
        socket_bind_stream_policies::evaluate_policies as evaluate_socket_bind_stream_policies,
    },
};

#[lsm(hook = "file_open")]
pub fn file_open(ctx: LsmContext) -> i32 {
    unsafe {
        aya_ebpf::bpf_printk!(b"tails-pdp: file_open entry");
        let _ = POLICY_JUMP_TABLE.tail_call(&ctx, TAIL_IDX_FILE_OPEN_STATIC);
    }
    0
}

#[lsm(hook = "socket_bind")]
pub fn socket_bind(ctx: LsmContext) -> i32 {
    let subject = ctx.uid();
    let resource = read_socket_bind_resource(&ctx);

    if evaluate_socket_bind_static_policies(subject, &resource) != 0 {
        unsafe {
            aya_ebpf::bpf_printk!(b"tails-pdp: socket_bind deny static");
        }
        return -1;
    }

    let current_time = CURRENT_TIME.get(0).copied().unwrap_or(0);
    if evaluate_socket_bind_stream_policies(subject, &resource, current_time) != 0 {
        unsafe {
            aya_ebpf::bpf_printk!(b"tails-pdp: socket_bind deny stream");
        }
        return -1;
    }

    unsafe {
        aya_ebpf::bpf_printk!(b"tails-pdp: socket_bind permit");
    }
    0
}

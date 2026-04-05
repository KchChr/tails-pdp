use aya_ebpf::{EbpfContext, macros::lsm, programs::LsmContext};

use crate::maps::{POLICY_JUMP_TABLE, TAIL_IDX_FILE_OPEN_STATIC, TAIL_IDX_SOCKET_BIND_STATIC};

#[lsm(hook = "file_open")]
pub fn file_open(ctx: LsmContext) -> i32 {
    let subject = ctx.uid();
    unsafe {
        aya_ebpf::bpf_printk!(b"file_open uid=%d", subject);
        let _ = POLICY_JUMP_TABLE.tail_call(&ctx, TAIL_IDX_FILE_OPEN_STATIC);
    }
    0
}

#[lsm(hook = "socket_bind")]
pub fn socket_bind(ctx: LsmContext) -> i32 {
    let subject = ctx.uid();
    unsafe {
        aya_ebpf::bpf_printk!(b"socket_bind uid=%d", subject);
        let _ = POLICY_JUMP_TABLE.tail_call(&ctx, TAIL_IDX_SOCKET_BIND_STATIC);
    }
    0
}

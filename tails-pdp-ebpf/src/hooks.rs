use aya_ebpf::{EbpfContext, macros::lsm, programs::LsmContext};

use crate::maps::{
    FILE_OPEN_JUMP_TABLE, SOCKET_BIND_JUMP_TABLE, TAIL_IDX_FILE_OPEN_STATIC,
    TAIL_IDX_SOCKET_BIND_STATIC,
};

#[lsm(hook = "file_open")]
pub fn file_open(ctx: LsmContext) -> i32 {
    let subject = ctx.uid();
    crate::debug_printk!(b"file_open uid=%d", subject);
    unsafe {
        let _ = FILE_OPEN_JUMP_TABLE.tail_call(&ctx, TAIL_IDX_FILE_OPEN_STATIC);
    }
    0
}

#[lsm(hook = "socket_bind")]
pub fn socket_bind(ctx: LsmContext) -> i32 {
    let subject = ctx.uid();
    crate::debug_printk!(b"socket_bind uid=%d", subject);
    unsafe {
        let _ = SOCKET_BIND_JUMP_TABLE.tail_call(&ctx, TAIL_IDX_SOCKET_BIND_STATIC);
    }
    0
}

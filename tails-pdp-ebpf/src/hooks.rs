use aya_ebpf::{EbpfContext, macros::lsm, programs::LsmContext};
use tails_pdp_common::LSM_DENY;

use crate::maps::{FILE_OPEN_JUMP_TABLE, TAIL_IDX_FILE_OPEN_STATIC};

#[lsm(hook = "file_open")]
pub fn file_open(ctx: LsmContext) -> i32 {
    // BPF LSM appends the previous program's return value after the hook's declared arguments.
    // Preserve an earlier denial instead of overriding another security module.
    let previous_return: i32 = ctx.arg(1);
    if previous_return != 0 {
        return previous_return;
    }

    let subject = ctx.uid();
    crate::debug_printk!(b"file_open uid=%d", subject);
    // SAFETY: the userspace loader installs an LSM program in this fixed program-array slot.
    // A successful tail call never returns. Reaching the return below therefore means that the
    // enforcement chain is incomplete, which must fail closed.
    unsafe {
        let _ = FILE_OPEN_JUMP_TABLE.tail_call(&ctx, TAIL_IDX_FILE_OPEN_STATIC);
    }
    crate::debug_printk!(b"file_open tail_call=failed stage=static");
    LSM_DENY
}

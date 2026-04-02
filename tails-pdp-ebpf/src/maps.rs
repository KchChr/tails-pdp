use aya_ebpf::{
    macros::map,
    maps::{Array, ProgramArray},
};
use tails_pdp_common::{
    FILE_OPEN_STATIC_POLICY_MAX_ENTRIES, FILE_OPEN_STREAM_POLICY_MAX_ENTRIES, FileOpenStaticPolicy,
    FileOpenStreamPolicy, SOCKET_BIND_STATIC_POLICY_MAX_ENTRIES,
    SOCKET_BIND_STREAM_POLICY_MAX_ENTRIES, SocketBindStaticPolicy, SocketBindStreamPolicy,
};

pub(crate) const TAIL_IDX_FILE_OPEN_STATIC: u32 = 0;
pub(crate) const TAIL_IDX_FILE_OPEN_STREAM: u32 = 1;
pub(crate) const TAIL_IDX_COMBINE: u32 = 2;

#[map]
pub(crate) static POLICY_JUMP_TABLE: ProgramArray = ProgramArray::with_max_entries(3, 0);

#[map]
pub(crate) static DECISIONS: Array<i32> = Array::with_max_entries(1, 0);

#[map]
pub(crate) static FILE_OPEN_STATIC_POLICIES: Array<FileOpenStaticPolicy> =
    Array::pinned(FILE_OPEN_STATIC_POLICY_MAX_ENTRIES, 0);

#[map]
pub(crate) static FILE_OPEN_STREAM_POLICIES: Array<FileOpenStreamPolicy> =
    Array::pinned(FILE_OPEN_STREAM_POLICY_MAX_ENTRIES, 0);

#[map]
pub(crate) static SOCKET_BIND_STATIC_POLICIES: Array<SocketBindStaticPolicy> =
    Array::pinned(SOCKET_BIND_STATIC_POLICY_MAX_ENTRIES, 0);

#[map]
pub(crate) static SOCKET_BIND_STREAM_POLICIES: Array<SocketBindStreamPolicy> =
    Array::pinned(SOCKET_BIND_STREAM_POLICY_MAX_ENTRIES, 0);

#[map]
pub(crate) static CURRENT_TIME: Array<u64> = Array::pinned(1, 0);

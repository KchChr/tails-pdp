use aya_ebpf::{
    macros::map,
    maps::{Array, HashMap, PerCpuArray, ProgramArray},
};
use tails_pdp_common::{
    ATTRIBUTE_GENERATION_MAX_ENTRIES, ATTRIBUTE_MAP_MAX_ENTRIES, AttributeKey, AttributeValue,
    FILE_OPEN_STATIC_POLICY_MAX_ENTRIES, FILE_OPEN_STREAM_POLICY_MAX_ENTRIES, FileOpenStaticPolicy,
    FileOpenStreamPolicy, Iso8601TimeParts, POLICY_GENERATION_MAX_ENTRIES,
    SOCKET_BIND_STATIC_POLICY_MAX_ENTRIES, SOCKET_BIND_STREAM_POLICY_MAX_ENTRIES,
    STREAM_ATTRIBUTE_MAX_ENTRIES, SocketBindStaticPolicy, SocketBindStreamPolicy,
};

pub(crate) const TAIL_IDX_FILE_OPEN_STATIC: u32 = 0;
pub(crate) const TAIL_IDX_FILE_OPEN_STREAM: u32 = 1;
pub(crate) const TAIL_IDX_FILE_OPEN_COMBINE: u32 = 2;
pub(crate) const TAIL_IDX_SOCKET_BIND_STATIC: u32 = 0;
pub(crate) const TAIL_IDX_SOCKET_BIND_STREAM: u32 = 1;
pub(crate) const TAIL_IDX_SOCKET_BIND_COMBINE: u32 = 2;
pub(crate) const DECISION_DENY_IDX: u32 = 0;
pub(crate) const DECISION_PERMIT_IDX: u32 = 1;
pub(crate) const DECISION_GENERATION_IDX: u32 = 2;

#[map]
pub(crate) static FILE_OPEN_JUMP_TABLE: ProgramArray = ProgramArray::with_max_entries(3, 0);

#[map]
pub(crate) static SOCKET_BIND_JUMP_TABLE: ProgramArray = ProgramArray::with_max_entries(3, 0);

#[map]
pub(crate) static DECISIONS: PerCpuArray<u32> = PerCpuArray::with_max_entries(3, 0);

#[map]
pub(crate) static DEBUG_LOGGING: Array<u32> = Array::with_max_entries(1, 0);

#[map]
pub(crate) static POLICY_GENERATION: Array<u32> = Array::pinned(POLICY_GENERATION_MAX_ENTRIES, 0);

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

#[map]
pub(crate) static CURRENT_TIME_ISO8601: Array<Iso8601TimeParts> = Array::pinned(1, 0);

#[map]
pub(crate) static CURRENT_DEFCON: Array<u32> = Array::pinned(STREAM_ATTRIBUTE_MAX_ENTRIES, 0);

#[map]
pub(crate) static ATTRIBUTE_GENERATION: Array<u32> =
    Array::pinned(ATTRIBUTE_GENERATION_MAX_ENTRIES, 0);

#[map]
pub(crate) static ATTRIBUTES: HashMap<AttributeKey, AttributeValue> =
    HashMap::pinned(ATTRIBUTE_MAP_MAX_ENTRIES, 0);

use aya_ebpf::{
    macros::map,
    maps::{Array, ProgramArray},
};
use tails_pdp_common::{StaticPolicy, StreamPolicy};

pub(crate) const TAIL_IDX_POLICY_1: u32 = 0;
pub(crate) const TAIL_IDX_POLICY_2: u32 = 1;
pub(crate) const COMBINE: u32 = 2;
pub(crate) const STATIC_POLICY_MAX_ENTRIES: u32 = 128;
pub(crate) const STREAM_POLICY_MAX_ENTRIES: u32 = 128;

#[map]
pub(crate) static POLICY_JUMP_TABLE: ProgramArray = ProgramArray::with_max_entries(3, 0);

#[map]
pub(crate) static DECISIONS: Array<i32> = Array::with_max_entries(1, 0);

#[map]
pub(crate) static STATIC_POLICY: Array<StaticPolicy> = Array::pinned(STATIC_POLICY_MAX_ENTRIES, 0);

#[map]
pub(crate) static STREAM_POLICY: Array<StreamPolicy> = Array::pinned(STREAM_POLICY_MAX_ENTRIES, 0);

#[map]
pub(crate) static CURRENT_TIME: Array<u64> = Array::pinned(1, 0);

#![no_std]
#![no_main]

use aya_ebpf::{
    EbpfContext,
    cty::c_void,
    helpers::bpf_get_current_pid_tgid,
    macros::{lsm, map},
    maps::{HashMap, ProgramArray},
    programs::LsmContext,
};
use aya_log_ebpf::info;
use tails_pdp_common::{
    AuthorizationSubscription, DECISION_DENY, DECISION_INDETERMINATE, DECISION_PERMIT,
    DecisionFlags, TAIL_IDX_COMBINER, TAIL_IDX_POLICY_1, TAIL_IDX_POLICY_2, TAIL_IDX_POLICY_3,
};

const PIPELINE_LEN: u32 = 4;

#[map]
static POLICY_JUMP_TABLE: ProgramArray = ProgramArray::with_max_entries(PIPELINE_LEN, 0);

#[map]
static AUTHORIZATION_SUBSCRIPTION: HashMap<u64, AuthorizationSubscription> =
    HashMap::with_max_entries(1024, 0);

#[map]
static DECISIONS_FLAG: HashMap<u64, DecisionFlags> = HashMap::with_max_entries(1024, 0);

#[lsm(hook = "file_open")]
pub fn file_open(ctx: LsmContext) -> i32 {
    match try_file_open(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[lsm(hook = "file_open")]
pub fn policy_1(ctx: LsmContext) -> i32 {
    match try_policy_1(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[lsm(hook = "file_open")]
pub fn policy_2(ctx: LsmContext) -> i32 {
    match try_policy_2(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[lsm(hook = "file_open")]
pub fn policy_3(ctx: LsmContext) -> i32 {
    match try_policy_3(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[lsm(hook = "file_open")]
pub fn policy_combiner(ctx: LsmContext) -> i32 {
    match try_policy_combiner(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_file_open(ctx: &LsmContext) -> Result<i32, i32> {
    let previous_ret: i32 = ctx.arg(2);
    if previous_ret != 0 {
        return Ok(previous_ret);
    }

    let request_id = bpf_get_current_pid_tgid();
    let file_ptr = ctx.arg::<*const c_void>(0) as u64;
    let cred_ptr = ctx.arg::<*const c_void>(1) as u64;
    let subscription = AuthorizationSubscription {
        request_id,
        pid: request_id as u32,
        tgid: (request_id >> 32) as u32,
        uid: ctx.uid(),
        gid: ctx.gid(),
        file_ptr,
        cred_ptr,
    };

    AUTHORIZATION_SUBSCRIPTION.insert(&request_id, &subscription, 0)?;
    DECISIONS_FLAG.insert(&request_id, &DecisionFlags::all_indeterminate(), 0)?;

    info!(
        ctx,
        "file_open entry request_id={} -> policy pipeline", request_id
    );
    unsafe {
        let _ = POLICY_JUMP_TABLE.tail_call(ctx, TAIL_IDX_POLICY_1);
    }

    // Fail-open while initial policy logic is mocked.
    Ok(0)
}

fn try_policy_1(ctx: &LsmContext) -> Result<i32, i32> {
    let request_id = bpf_get_current_pid_tgid();
    set_policy_decision(request_id, TAIL_IDX_POLICY_1, DECISION_PERMIT)?;
    info!(ctx, "policy_1 request_id={} -> Permit", request_id);

    unsafe {
        let _ = POLICY_JUMP_TABLE.tail_call(ctx, TAIL_IDX_POLICY_2);
    }

    Ok(0)
}

fn try_policy_2(ctx: &LsmContext) -> Result<i32, i32> {
    let request_id = bpf_get_current_pid_tgid();
    set_policy_decision(request_id, TAIL_IDX_POLICY_2, DECISION_PERMIT)?;
    info!(ctx, "policy_2 request_id={} -> Permit", request_id);

    unsafe {
        let _ = POLICY_JUMP_TABLE.tail_call(ctx, TAIL_IDX_POLICY_3);
    }

    Ok(0)
}

fn try_policy_3(ctx: &LsmContext) -> Result<i32, i32> {
    let request_id = bpf_get_current_pid_tgid();
    set_policy_decision(request_id, TAIL_IDX_POLICY_3, DECISION_PERMIT)?;
    info!(ctx, "policy_3 request_id={} -> Permit", request_id);

    unsafe {
        let _ = POLICY_JUMP_TABLE.tail_call(ctx, TAIL_IDX_COMBINER);
    }

    Ok(0)
}

fn try_policy_combiner(ctx: &LsmContext) -> Result<i32, i32> {
    let request_id = bpf_get_current_pid_tgid();
    let combined = unsafe {
        DECISIONS_FLAG
            .get(&request_id)
            .map(DecisionFlags::combine)
            .unwrap_or(DECISION_INDETERMINATE)
    };

    // Cleanup request-scoped state.
    let _ = DECISIONS_FLAG.remove(&request_id);
    let _ = AUTHORIZATION_SUBSCRIPTION.remove(&request_id);

    info!(
        ctx,
        "policy_combiner request_id={} -> combined={}", request_id, combined
    );

    let decision = match combined {
        DECISION_DENY => -1,
        DECISION_PERMIT => 0,
        DECISION_INDETERMINATE => 0,
        _ => 0,
    };

    Ok(decision)
}

fn set_policy_decision(request_id: u64, policy_slot: u32, decision: u8) -> Result<(), i32> {
    let decisions_ptr = DECISIONS_FLAG.get_ptr_mut(&request_id).ok_or(-1)?;
    unsafe {
        match policy_slot {
            TAIL_IDX_POLICY_1 => (*decisions_ptr).policy_1 = decision,
            TAIL_IDX_POLICY_2 => (*decisions_ptr).policy_2 = decision,
            TAIL_IDX_POLICY_3 => (*decisions_ptr).policy_3 = decision,
            _ => return Err(-1),
        }
    }

    Ok(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";

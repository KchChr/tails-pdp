#![no_std]
#![no_main]

use aya_ebpf::{helpers::{bpf_get_current_pid_tgid, bpf_get_current_uid_gid}, macros::{lsm, map}, maps::{Array, HashMap, ProgramArray}, programs::LsmContext, EbpfContext};
use log::info;
use tails_pdp_common::{Action, AuthorizationSubscription};

const TAIL_IDX_POLICY_1: u32 = 0;
const TAIL_IDX_POLICY_2: u32 = 1;
const TAIL_IDX_POLICY_3: u32 = 2;
const COMBINE: u32 = 3;
const AUTH_SUBS_MAX_ENTRIES: u32 = 1;

#[map]
static POLICY_JUMP_TABLE: ProgramArray = ProgramArray::with_max_entries(4, 0);

#[map]
static DECISIONS: Array<i32> = Array::with_max_entries(1, 0);

#[map]
static AUTHORIZATION_SUBSCRIPTIONS: HashMap<u64, AuthorizationSubscription> =
    HashMap::with_max_entries(AUTH_SUBS_MAX_ENTRIES, 0);

fn create_and_store_authorization_subscription(
    uid: u32,
    gid: u32,
    action: Action,
    resource_id: u64,
) -> Result<u64, i64> {
    let pid_tgid = unsafe { bpf_get_current_pid_tgid() };
    let uid_gid = unsafe { bpf_get_current_uid_gid() };
    let subject_uid = uid as u32;
    let subject_gid = gid as u32;
    let pid = pid_tgid as u32;
    let tgid = (pid_tgid >> 32) as u32;

    let subscription = AuthorizationSubscription {
        subject_uid,
        subject_gid,
        action: action.as_u8(),
        _pad: [0; 3],
        pid,
        tgid,
        resource_id,
    };

    AUTHORIZATION_SUBSCRIPTIONS
        .insert(pid_tgid, subscription, 0)
        .map(|_| pid_tgid)
        .map_err(|e| e as i64)
}

#[lsm(hook = "file_open")]
pub fn file_open(ctx: LsmContext) -> i32 {
    let uid = &ctx.uid();
    let gid = &ctx.gid();
    info!(&ctx, "uid: {}", &uid);
    info!(&ctx, "gid: {}", &gid);



    let store_result = create_and_store_authorization_subscription(uid, gid, Action::FileOpen, 0);

    unsafe {
        aya_ebpf::bpf_printk!(b"tails-pdp: file_open entry");
        if store_result.is_err() {
            aya_ebpf::bpf_printk!(b"tails-pdp: authz sub store failed");
        }
        let _ = POLICY_JUMP_TABLE.tail_call(&ctx, TAIL_IDX_POLICY_1);
    }
    0
}

#[lsm(hook = "task_setnice")]
pub fn task_setnice(ctx: LsmContext) -> i32 {

    let uid = ctx.uid();
    let gid = ctx.gid();

    let store_result = create_and_store_authorization_subscription(uid, gid, Action::TaskSetNice, 0);

    unsafe {
        aya_ebpf::bpf_printk!(b"tails-pdp: task_setnice entry");
        if store_result.is_err() {
            aya_ebpf::bpf_printk!(b"tails-pdp: authz sub store failed");
        }
    }

    0
}

#[lsm(hook = "file_open")]
pub fn policy_1(ctx: LsmContext) -> i32 {
    let _ = DECISIONS.set(0, 0, 0);
    unsafe {
        aya_ebpf::bpf_printk!(b"tails-pdp: policy_1");
        let _ = POLICY_JUMP_TABLE.tail_call(&ctx, TAIL_IDX_POLICY_2);
    }

    0
}

#[lsm(hook = "file_open")]
pub fn policy_2(ctx: LsmContext) -> i32 {
    unsafe {
        aya_ebpf::bpf_printk!(b"tails-pdp: policy_2");
        let _ = POLICY_JUMP_TABLE.tail_call(&ctx, TAIL_IDX_POLICY_3);
    }
    0
}

#[lsm(hook = "file_open")]
pub fn policy_3(ctx: LsmContext) -> i32 {
    unsafe {
        aya_ebpf::bpf_printk!(b"tails-pdp: policy_3");
        let _ = POLICY_JUMP_TABLE.tail_call(&ctx, COMBINE);
    }
    0
}

#[lsm(hook = "file_open")]
pub fn combine(ctx: LsmContext) -> i32 {
    unsafe {
        aya_ebpf::bpf_printk!(b"tails-pdp: combine");
    }
    match DECISIONS.get(0) {
        Some(v) if *v != 0 => {
            unsafe {
                aya_ebpf::bpf_printk!(b"DENY");
            }
            -1
        } // deny
        _ => {
            unsafe {
                aya_ebpf::bpf_printk!(b"PERMIT");
            }
            0
        } // permit/default
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";

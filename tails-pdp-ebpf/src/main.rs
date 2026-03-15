#![no_std]
#![no_main]

mod vmlinux;

use core::ptr::addr_of;

use aya_ebpf::{
    EbpfContext,
    helpers::{bpf_probe_read_kernel, bpf_probe_read_kernel_str_bytes},
    macros::{lsm, map},
    maps::{Array, ProgramArray},
    programs::LsmContext,
};
use tails_pdp_common::{ANY_SUBJECT, COMMAND_LEN, PolicyAction, RESOURCE_LEN, StaticPolicy};

const TAIL_IDX_POLICY_1: u32 = 0;
const TAIL_IDX_POLICY_2: u32 = 1;
const TAIL_IDX_POLICY_3: u32 = 2;
const COMBINE: u32 = 3;
const STATIC_POLICY_MAX_ENTRIES: u32 = 128;

#[map]
static POLICY_JUMP_TABLE: ProgramArray = ProgramArray::with_max_entries(4, 0);

#[map]
static DECISIONS: Array<i32> = Array::with_max_entries(1, 0);

#[map]
static STATIC_POLICY: Array<StaticPolicy> = Array::pinned(STATIC_POLICY_MAX_ENTRIES, 0);

fn matches_subject(subject: u32, current_subject: u32) -> bool {
    subject == ANY_SUBJECT || subject == current_subject
}

fn matches_bytes<const N: usize>(policy_value: &[u8; N], current_value: &[u8; N]) -> bool {
    policy_value[0] == 0 || policy_value == current_value
}

fn read_file_open_resource(ctx: &LsmContext) -> [u8; RESOURCE_LEN] {
    let mut resource = [0; RESOURCE_LEN];
    let file_ptr: *const vmlinux::file = ctx.arg(0);
    if file_ptr.is_null() {
        return resource;
    }

    let Ok(dentry_ptr) = (unsafe { bpf_probe_read_kernel(addr_of!((*file_ptr).f_path.dentry)) })
    else {
        return resource;
    };
    if dentry_ptr.is_null() {
        return resource;
    }

    let Ok(name_ptr) = (unsafe { bpf_probe_read_kernel(addr_of!((*dentry_ptr).d_name.name)) })
    else {
        return resource;
    };
    if name_ptr.is_null() {
        return resource;
    }

    let _ = unsafe { bpf_probe_read_kernel_str_bytes(name_ptr.cast(), &mut resource) };
    resource
}

fn evaluate_static_policy(
    current_subject: u32,
    current_action: PolicyAction,
    current_command: &[u8; COMMAND_LEN],
    current_resource: &[u8; RESOURCE_LEN],
    policy: &StaticPolicy,
) -> Option<i32> {
    if policy.enabled == 0 {
        return None;
    }

    if policy.action != current_action {
        return None;
    }

    if !matches_subject(policy.subject, current_subject) {
        return None;
    }

    if !matches_bytes(&policy.command, current_command) {
        return None;
    }

    if !matches_bytes(&policy.resource, current_resource) {
        return None;
    }

    Some(policy.entitlement.decision())
}

fn evaluate_policies(
    current_subject: u32,
    current_action: PolicyAction,
    current_command: &[u8; COMMAND_LEN],
    current_resource: &[u8; RESOURCE_LEN],
) -> i32 {
    let mut decision = 0;
    let mut index = 0;

    while index < STATIC_POLICY_MAX_ENTRIES {
        if let Some(policy) = STATIC_POLICY.get(index) {
            if let Some(policy_decision) = evaluate_static_policy(
                current_subject,
                current_action,
                current_command,
                current_resource,
                policy,
            ) {
                if policy_decision != 0 {
                    decision = 1;
                    break;
                }
            }
        }
        index += 1;
    }

    decision
}

#[lsm(hook = "file_open")]
pub fn file_open(ctx: LsmContext) -> i32 {
    unsafe {
        aya_ebpf::bpf_printk!(b"tails-pdp: file_open entry");
        let _ = POLICY_JUMP_TABLE.tail_call(&ctx, TAIL_IDX_POLICY_1);
    }
    0
}

#[lsm(hook = "task_setnice")]
pub fn task_setnice(ctx: LsmContext) -> i32 {
    let subject = ctx.uid();
    let command = ctx.command().unwrap_or([0; COMMAND_LEN]);
    let resource = [0; RESOURCE_LEN];
    let decision = evaluate_policies(subject, PolicyAction::TaskSetNice, &command, &resource);

    unsafe {
        aya_ebpf::bpf_printk!(b"tails-pdp: task_setnice entry");
    }

    if decision != 0 { -1 } else { 0 }
}

#[lsm(hook = "file_open")]
pub fn evaluate_static_policys(ctx: LsmContext) -> i32 {
    let subject = ctx.uid();
    let command = ctx.command().unwrap_or([0; COMMAND_LEN]);
    let resource = read_file_open_resource(&ctx);
    let decision = evaluate_policies(subject, PolicyAction::FileOpen, &command, &resource);
    let _ = DECISIONS.set(0, decision, 0);

    unsafe {
        aya_ebpf::bpf_printk!(b"tails-pdp: evaluate_static_policys");
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
pub fn combine(_ctx: LsmContext) -> i32 {
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

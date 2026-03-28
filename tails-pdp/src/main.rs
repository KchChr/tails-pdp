use anyhow::Context;
use aya::{Btf, EbpfLoader, VerifierLogLevel, maps::ProgramArray, programs::Lsm};
#[rustfmt::skip]
use log::debug;
use std::fs;

use tails_pdp::{
    BPF_PIN_DIRECTORY, LSM_PROGRAMS, TAIL_PROGRAMS,
    policy_loader::{load_static_policies, load_stream_policies, verify_pinned_map_layouts},
    time::{open_current_time_map, run_current_time_updater},
};
use tails_pdp_common::{
    ANY_SUBJECT, Entitlement, PolicyAction, StaticPolicy, StreamOperator, StreamPolicy,
};
use tokio::signal;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    // let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
    //     env!("OUT_DIR"),
    //     "/tails-pdp"
    // )))?;

    fs::create_dir_all(BPF_PIN_DIRECTORY)
        .with_context(|| format!("failed to create {BPF_PIN_DIRECTORY}"))?;
    verify_pinned_map_layouts()?;

    let mut ebpf = EbpfLoader::new()
        .default_map_pin_directory(BPF_PIN_DIRECTORY)
        .verifier_log_level(VerifierLogLevel::VERBOSE | VerifierLogLevel::STATS)
        .load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/tails-pdp"
        )))?;

    let btf = Btf::from_sys_fs()?;
    for spec in LSM_PROGRAMS {
        let program: &mut Lsm = ebpf
            .program_mut(spec.name)
            .with_context(|| format!("program '{}' not found", spec.name))?
            .try_into()
            .with_context(|| format!("program '{}' has unexpected type", spec.name))?;
        program
            .load(spec.hook, &btf)
            .with_context(|| format!("failed to load '{}' on hook '{}'", spec.name, spec.hook))?;
    }

    let mut jump_table = ProgramArray::try_from(
        ebpf.take_map("POLICY_JUMP_TABLE")
            .context("map 'POLICY_JUMP_TABLE' not found")?,
    )
    .context("failed to open POLICY_JUMP_TABLE")?;
    let static_policies = [StaticPolicy::new(
        Entitlement::Deny,
        ANY_SUBJECT,
        PolicyAction::FileOpen,
        "cat",
        "",
    )];
    let stream_policies = [StreamPolicy::time(
        Entitlement::Permit,
        0,
        PolicyAction::FileOpen,
        StreamOperator::LessThan,
        10,
        5,
    )];
    load_static_policies(&mut ebpf, &static_policies)?;
    load_stream_policies(&mut ebpf, &stream_policies)?;
    let mut current_time = open_current_time_map(&mut ebpf)?;

    for (index, program_name) in TAIL_PROGRAMS {
        let program: &Lsm = ebpf
            .program(program_name)
            .with_context(|| format!("program '{program_name}' not found"))?
            .try_into()
            .with_context(|| format!("program '{program_name}' has unexpected type"))?;
        jump_table
            .set(index, program.fd()?, 0)
            .with_context(|| format!("failed to set jump table slot for '{program_name}'"))?;
    }

    for spec in LSM_PROGRAMS {
        if !spec.attach {
            continue;
        }
        let program: &mut Lsm = ebpf
            .program_mut(spec.name)
            .with_context(|| format!("program '{}' not found", spec.name))?
            .try_into()
            .with_context(|| format!("program '{}' has unexpected type", spec.name))?;
        program
            .attach()
            .with_context(|| format!("failed to attach '{}'", spec.name))?;
    }

    println!("Waiting for Ctrl-C...");
    tokio::select! {
        result = run_current_time_updater(&mut current_time) => result?,
        result = signal::ctrl_c() => result?,
    }
    println!("Exiting...");

    Ok(())
}

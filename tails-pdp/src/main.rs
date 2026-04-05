use anyhow::Context;
use aya::{Btf, EbpfLoader, VerifierLogLevel, maps::ProgramArray, programs::Lsm};
#[rustfmt::skip]
use log::debug;
use std::fs;

use tails_pdp::{
    BPF_PIN_DIRECTORY, FILE_OPEN_TAIL_PROGRAMS, LSM_PROGRAMS, SOCKET_BIND_TAIL_PROGRAMS,
    policy_loader::{
        load_file_open_static_policies, load_file_open_stream_policies,
        load_socket_bind_static_policies, load_socket_bind_stream_policies,
        verify_pinned_map_layouts,
    },
    time::{open_current_time_map, run_current_time_updater},
};
use tails_pdp_common::{
    Entitlement, FileOpenStaticPolicy, FileOpenStreamPolicy, SocketBindStaticPolicy,
    SocketBindStreamPolicy,
};
use tokio::signal;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

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

    let mut file_open_jump_table = ProgramArray::try_from(
        ebpf.take_map("FILE_OPEN_JUMP_TABLE")
            .context("map 'FILE_OPEN_JUMP_TABLE' not found")?,
    )
    .context("failed to open FILE_OPEN_JUMP_TABLE")?;

    let mut socket_bind_jump_table = ProgramArray::try_from(
        ebpf.take_map("SOCKET_BIND_JUMP_TABLE")
            .context("map 'SOCKET_BIND_JUMP_TABLE' not found")?,
    )
    .context("failed to open SOCKET_BIND_JUMP_TABLE")?;

    let file_open_static_policies = [
        FileOpenStaticPolicy::new(Entitlement::Deny, 1000, "cat", "/home/hntr/test.txt"),
        FileOpenStaticPolicy::new(Entitlement::Permit, 1000, "tail", "/home/hntr/test.txt"),
        FileOpenStaticPolicy::new(Entitlement::Deny, 1000, "cat", "/home/hntr/test2.txt"),
    ];
    let file_open_stream_policies: [FileOpenStreamPolicy; 0] = [];
    let socket_bind_static_policies: [SocketBindStaticPolicy; 0] = [];
    let socket_bind_stream_policies: [SocketBindStreamPolicy; 0] = [];

    load_file_open_static_policies(&mut ebpf, &file_open_static_policies)?;
    load_file_open_stream_policies(&mut ebpf, &file_open_stream_policies)?;
    load_socket_bind_static_policies(&mut ebpf, &socket_bind_static_policies)?;
    load_socket_bind_stream_policies(&mut ebpf, &socket_bind_stream_policies)?;

    let mut current_time = open_current_time_map(&mut ebpf)?;

    for (index, program_name) in FILE_OPEN_TAIL_PROGRAMS {
        let program: &Lsm = ebpf
            .program(program_name)
            .with_context(|| format!("program '{program_name}' not found"))?
            .try_into()
            .with_context(|| format!("program '{program_name}' has unexpected type"))?;
        file_open_jump_table
            .set(index, program.fd()?, 0)
            .with_context(|| {
                format!("failed to set file_open jump table slot for '{program_name}'")
            })?;
    }

    for (index, program_name) in SOCKET_BIND_TAIL_PROGRAMS {
        let program: &Lsm = ebpf
            .program(program_name)
            .with_context(|| format!("program '{program_name}' not found"))?
            .try_into()
            .with_context(|| format!("program '{program_name}' has unexpected type"))?;
        socket_bind_jump_table
            .set(index, program.fd()?, 0)
            .with_context(|| {
                format!("failed to set socket_bind jump table slot for '{program_name}'")
            })?;
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

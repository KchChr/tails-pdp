use std::{env, fs};

use anyhow::Context;
use aya::{
    Btf, EbpfLoader, VerifierLogLevel,
    maps::{Array, ProgramArray},
    programs::Lsm,
};
use log::{debug, info};
use tails_pdp::{
    BPF_PIN_DIRECTORY, FILE_OPEN_TAIL_PROGRAMS, LSM_PROGRAMS,
    monitor::run_policy_monitor,
    policy_loader::verify_pinned_map_layouts,
    policy_source::PolicyDirectorySync,
    stream_attributes::{open_attribute_maps, run_attribute_updater, write_current_attributes},
    time::{open_current_time_maps, run_current_time_updater, write_current_time},
};
use tokio::signal;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

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

    let mut debug_logging = Array::try_from(
        ebpf.take_map("DEBUG_LOGGING")
            .context("map 'DEBUG_LOGGING' not found")?,
    )
    .context("failed to open DEBUG_LOGGING")?;
    debug_logging
        .set(0, u32::from(env_flag_enabled("TAILS_PDP_EBPF_DEBUG")), 0)
        .context("failed to configure DEBUG_LOGGING")?;

    let mut file_open_jump_table = ProgramArray::try_from(
        ebpf.take_map("FILE_OPEN_JUMP_TABLE")
            .context("map 'FILE_OPEN_JUMP_TABLE' not found")?,
    )
    .context("failed to open FILE_OPEN_JUMP_TABLE")?;

    let (mut current_time, mut current_time_iso8601) = open_current_time_maps(&mut ebpf)?;
    let mut attribute_maps = open_attribute_maps(&mut ebpf)?;
    let mut policy_sync = PolicyDirectorySync::new()?;

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

    policy_sync.sync_initial()?;
    write_current_time(&mut current_time, &mut current_time_iso8601)?;
    write_current_attributes(&mut attribute_maps)?;
    info!(
        "Watching policy directory '{}'",
        policy_sync.directory().display()
    );
    info!("Waiting for Ctrl-C...");

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

    tokio::select! {
        result = run_current_time_updater(&mut current_time, &mut current_time_iso8601) => result?,
        result = run_attribute_updater(&mut attribute_maps) => result?,
        result = policy_sync.run() => result?,
        result = run_policy_monitor() => result?,
        result = signal::ctrl_c() => result?,
    }
    info!("Exiting...");

    Ok(())
}

fn env_flag_enabled(name: &str) -> bool {
    match env::var(name) {
        Ok(value) => !matches!(
            value.as_str(),
            "" | "0" | "false" | "False" | "FALSE" | "off" | "Off" | "OFF" | "no" | "No" | "NO"
        ),
        Err(_) => false,
    }
}

use anyhow::Context;
use aya::{
    Btf, EbpfLoader, VerifierLogLevel,
    maps::{Array, ProgramArray},
    programs::Lsm,
};
#[rustfmt::skip]
use log::debug;
use std::{
    fs,
    time::{SystemTime, UNIX_EPOCH},
};

use tails_pdp_common::{Entitlement, PolicyAction, StaticPolicy, StreamOperator, StreamPolicy};
use tokio::{
    signal,
    time::{self, Duration},
};

const TAIL_IDX_POLICY_1: u32 = 0;
const TAIL_IDX_POLICY_2: u32 = 1;
const COMBINE: u32 = 2;
const BPF_PIN_DIRECTORY: &str = "/sys/fs/bpf/tails-pdp";
struct LsmProgramSpec {
    name: &'static str,
    hook: &'static str,
    attach: bool,
}

const LSM_PROGRAMS: [LsmProgramSpec; 5] = [
    LsmProgramSpec {
        name: "file_open",
        hook: "file_open",
        attach: true,
    },
    LsmProgramSpec {
        name: "task_setnice",
        hook: "task_setnice",
        attach: true,
    },
    LsmProgramSpec {
        name: "evaluate_static_policies",
        hook: "file_open",
        attach: false,
    },
    LsmProgramSpec {
        name: "evaluate_stream_policies",
        hook: "file_open",
        attach: false,
    },
    LsmProgramSpec {
        name: "combine",
        hook: "file_open",
        attach: false,
    },
];
const TAIL_PROGRAMS: [(u32, &str); 3] = [
    (TAIL_IDX_POLICY_1, "evaluate_static_policies"),
    (TAIL_IDX_POLICY_2, "evaluate_stream_policies"),
    (COMBINE, "combine"),
];

fn load_static_policies(ebpf: &mut aya::Ebpf) -> anyhow::Result<()> {
    let mut static_policy: Array<_, StaticPolicy> = Array::try_from(
        ebpf.take_map("STATIC_POLICY")
            .context("map 'STATIC_POLICY' not found")?,
    )
    .context("failed to open STATIC_POLICY")?;

    let example_policies = [StaticPolicy::new(
        Entitlement::Deny,
        0,
        PolicyAction::TaskSetNice,
        "",
        "",
    )];

    for index in 0..static_policy.len() {
        static_policy
            .set(index, StaticPolicy::disabled(), 0)
            .with_context(|| format!("failed to clear STATIC_POLICY entry {index}"))?;
    }

    for (index, policy) in example_policies.into_iter().enumerate() {
        static_policy
            .set(index as u32, policy, 0)
            .with_context(|| format!("failed to write STATIC_POLICY entry {index}"))?;
    }

    Ok(())
}

fn load_stream_policies(ebpf: &mut aya::Ebpf) -> anyhow::Result<()> {
    let mut stream_policy: Array<_, StreamPolicy> = Array::try_from(
        ebpf.take_map("STREAM_POLICY")
            .context("map 'STREAM_POLICY' not found")?,
    )
    .context("failed to open STREAM_POLICY")?;

    let example_policies = [StreamPolicy::time(
        Entitlement::Permit,
        PolicyAction::FileOpen,
        StreamOperator::LessThan,
        10,
        5,
    )];

    for index in 0..stream_policy.len() {
        stream_policy
            .set(index, StreamPolicy::disabled(), 0)
            .with_context(|| format!("failed to clear STREAM_POLICY entry {index}"))?;
    }

    for (index, policy) in example_policies.into_iter().enumerate() {
        stream_policy
            .set(index as u32, policy, 0)
            .with_context(|| format!("failed to write STREAM_POLICY entry {index}"))?;
    }

    Ok(())
}

fn current_unix_timestamp() -> anyhow::Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before UNIX_EPOCH")?
        .as_secs())
}

fn open_current_time_map(ebpf: &mut aya::Ebpf) -> anyhow::Result<Array<aya::maps::MapData, u64>> {
    Array::try_from(
        ebpf.take_map("CURRENT_TIME")
            .context("map 'CURRENT_TIME' not found")?,
    )
    .context("failed to open CURRENT_TIME")
}

fn write_current_time(current_time: &mut Array<aya::maps::MapData, u64>) -> anyhow::Result<()> {
    current_time
        .set(0, current_unix_timestamp()?, 0)
        .context("failed to write CURRENT_TIME[0]")?;
    Ok(())
}

async fn run_current_time_updater(
    current_time: &mut Array<aya::maps::MapData, u64>,
) -> anyhow::Result<()> {
    let mut ticker = time::interval(Duration::from_secs(1));

    write_current_time(current_time)?;

    loop {
        ticker.tick().await;
        write_current_time(current_time)?;
    }
}

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
    load_static_policies(&mut ebpf)?;
    load_stream_policies(&mut ebpf)?;
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

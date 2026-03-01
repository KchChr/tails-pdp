use anyhow::Context;
use aya::{Btf, maps::ProgramArray, programs::Lsm, VerifierLogLevel, EbpfLoader};
#[rustfmt::skip]
use log::debug;
use tokio::signal;

const TAIL_IDX_POLICY_1: u32 = 0;
const TAIL_IDX_POLICY_2: u32 = 1;
const TAIL_IDX_POLICY_3: u32 = 2;
const COMBINE: u32 = 3;
const LSM_PROGRAMS: [&str; 5] = ["file_open", "policy_1", "policy_2", "policy_3", "combine"];
const TAIL_PROGRAMS: [(u32, &str); 4] = [
    (TAIL_IDX_POLICY_1, "policy_1"),
    (TAIL_IDX_POLICY_2, "policy_2"),
    (TAIL_IDX_POLICY_3, "policy_3"),
    (COMBINE, "combine"),
];

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


    let mut ebpf = EbpfLoader::new()
        .verifier_log_level(VerifierLogLevel::VERBOSE | VerifierLogLevel::STATS)
        .load(aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/tails-pdp")))?;

    let btf = Btf::from_sys_fs()?;
    for program_name in LSM_PROGRAMS {
        let program: &mut Lsm = ebpf
            .program_mut(program_name)
            .with_context(|| format!("program '{program_name}' not found"))?
            .try_into()
            .with_context(|| format!("program '{program_name}' has unexpected type"))?;
        program
            .load("file_open", &btf)
            .with_context(|| format!("failed to load '{program_name}'"))?;
    }

    let mut jump_table = ProgramArray::try_from(
        ebpf.take_map("POLICY_JUMP_TABLE")
            .context("map 'POLICY_JUMP_TABLE' not found")?,
    )
    .context("failed to open POLICY_JUMP_TABLE")?;

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

    let program: &mut Lsm = ebpf
        .program_mut("file_open")
        .context("program 'file_open' not found")?
        .try_into()
        .context("program 'file_open' has unexpected type")?;
    program.attach()?;

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}

use anyhow::Context;
use aya::{Btf, maps::ProgramArray, programs::Lsm};
#[rustfmt::skip]
use log::debug;
use tokio::signal;

const TAIL_IDX_POLICY_1: u32 = 0;
const TAIL_IDX_POLICY_2: u32 = 1;
const TAIL_IDX_POLICY_3: u32 = 2;
const COMBINE: u32 = 3;

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
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/tails-pdp"
    )))?;
    let btf = Btf::from_sys_fs()?;
    for program_name in ["file_open", "policy_1", "policy_2", "policy_3", "combine"] {
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

    let policy_1: &Lsm = ebpf
        .program("policy_1")
        .context("program 'policy_1' not found")?
        .try_into()
        .context("program 'policy_1' has unexpected type")?;
    jump_table
        .set(TAIL_IDX_POLICY_1, policy_1.fd()?, 0)
        .context("failed to set jump table slot for policy_1")?;

    let policy_2: &Lsm = ebpf
        .program("policy_2")
        .context("program 'policy_2' not found")?
        .try_into()
        .context("program 'policy_2' has unexpected type")?;
    jump_table
        .set(TAIL_IDX_POLICY_2, policy_2.fd()?, 0)
        .context("failed to set jump table slot for policy_2")?;

    let policy_3: &Lsm = ebpf
        .program("policy_3")
        .context("program 'policy_3' not found")?
        .try_into()
        .context("program 'policy_3' has unexpected type")?;
    jump_table
        .set(TAIL_IDX_POLICY_3, policy_3.fd()?, 0)
        .context("failed to set jump table slot for policy_3")?;

    let combine: &Lsm = ebpf
        .program("combine")
        .context("program 'combine' not found")?
        .try_into()
        .context("program 'combine' has unexpected type")?;
    jump_table
        .set(COMBINE, combine.fd()?, 0)
        .context("failed to set jump table slot for combine")?;


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

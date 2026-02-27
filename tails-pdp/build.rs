use anyhow::{Context as _, anyhow};
use aya_build::Toolchain;

fn main() -> anyhow::Result<()> {
    // eBPF `no_std` binaries must not use unwinding; force abort panic strategy
    // for the nested cargo invocation performed by aya-build.
    println!("cargo:rerun-if-env-changed=CARGO_PROFILE_RELEASE_PANIC");
    println!("cargo:rerun-if-env-changed=CARGO_PROFILE_DEV_PANIC");
    unsafe {
        std::env::set_var("CARGO_PROFILE_RELEASE_PANIC", "abort");
        std::env::set_var("CARGO_PROFILE_DEV_PANIC", "abort");
    }

    let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .context("MetadataCommand::exec")?;
    let ebpf_package = packages
        .into_iter()
        .find(|cargo_metadata::Package { name, .. }| name.as_str() == "tails-pdp-ebpf")
        .ok_or_else(|| anyhow!("tails-pdp-ebpf package not found"))?;
    let cargo_metadata::Package {
        name,
        manifest_path,
        ..
    } = ebpf_package;
    let ebpf_package = aya_build::Package {
        name: name.as_str(),
        root_dir: manifest_path
            .parent()
            .ok_or_else(|| anyhow!("no parent for {manifest_path}"))?
            .as_str(),
        ..Default::default()
    };
    aya_build::build_ebpf([ebpf_package], Toolchain::default())
}

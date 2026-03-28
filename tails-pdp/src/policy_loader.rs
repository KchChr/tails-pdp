use anyhow::Context;
use aya::maps::Array;
use tails_pdp_common::{StaticPolicy, StreamPolicy};

pub fn load_static_policies(ebpf: &mut aya::Ebpf, policies: &[StaticPolicy]) -> anyhow::Result<()> {
    let mut static_policy: Array<_, StaticPolicy> = Array::try_from(
        ebpf.take_map("STATIC_POLICY")
            .context("map 'STATIC_POLICY' not found")?,
    )
    .context("failed to open STATIC_POLICY")?;

    for index in 0..static_policy.len() {
        static_policy
            .set(index, StaticPolicy::disabled(), 0)
            .with_context(|| format!("failed to clear STATIC_POLICY entry {index}"))?;
    }

    for (index, policy) in policies.iter().copied().enumerate() {
        static_policy
            .set(index as u32, policy, 0)
            .with_context(|| format!("failed to write STATIC_POLICY entry {index}"))?;
    }

    Ok(())
}

pub fn load_stream_policies(ebpf: &mut aya::Ebpf, policies: &[StreamPolicy]) -> anyhow::Result<()> {
    let mut stream_policy: Array<_, StreamPolicy> = Array::try_from(
        ebpf.take_map("STREAM_POLICY")
            .context("map 'STREAM_POLICY' not found")?,
    )
    .context("failed to open STREAM_POLICY")?;

    for index in 0..stream_policy.len() {
        stream_policy
            .set(index, StreamPolicy::disabled(), 0)
            .with_context(|| format!("failed to clear STREAM_POLICY entry {index}"))?;
    }

    for (index, policy) in policies.iter().copied().enumerate() {
        stream_policy
            .set(index as u32, policy, 0)
            .with_context(|| format!("failed to write STREAM_POLICY entry {index}"))?;
    }

    Ok(())
}

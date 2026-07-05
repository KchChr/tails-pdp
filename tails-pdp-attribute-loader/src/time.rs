use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context;
use aya::maps::{Array, MapData};
use tails_pdp_userspace_common::open_pinned_array;
use tokio::time::{self, Duration};

fn current_unix_timestamp() -> anyhow::Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before UNIX_EPOCH")?
        .as_secs())
}

pub fn open_current_time_map() -> anyhow::Result<Array<MapData, u64>> {
    open_pinned_array("CURRENT_TIME")
}

pub fn write_current_time(current_time: &mut Array<MapData, u64>) -> anyhow::Result<()> {
    current_time
        .set(0, current_unix_timestamp()?, 0)
        .context("failed to write CURRENT_TIME[0]")?;
    Ok(())
}

pub async fn run_current_time_updater(
    current_time: &mut Array<MapData, u64>,
) -> anyhow::Result<()> {
    let mut ticker = time::interval(Duration::from_secs(1));

    write_current_time(current_time)?;

    loop {
        ticker.tick().await;
        write_current_time(current_time)?;
    }
}

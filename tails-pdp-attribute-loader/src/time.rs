use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context;
use aya::maps::{Array, MapData};
use tails_pdp_common::Iso8601TimeParts;
use tails_pdp_userspace_common::open_pinned_array;
use tokio::time::{self, Duration};

fn current_unix_timestamp() -> anyhow::Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before UNIX_EPOCH")?
        .as_secs())
}

fn current_iso8601_time_parts() -> anyhow::Result<Iso8601TimeParts> {
    let timestamp = current_unix_timestamp()? as _;
    let mut now = libc::tm {
        tm_sec: 0,
        tm_min: 0,
        tm_hour: 0,
        tm_mday: 0,
        tm_mon: 0,
        tm_year: 0,
        tm_wday: 0,
        tm_yday: 0,
        tm_isdst: 0,
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        tm_gmtoff: 0,
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        tm_zone: core::ptr::null(),
        #[cfg(any(target_os = "linux", target_os = "android"))]
        tm_gmtoff: 0,
        #[cfg(any(target_os = "linux", target_os = "android"))]
        tm_zone: core::ptr::null(),
    };

    let result = unsafe { libc::gmtime_r(&timestamp, &mut now) };
    if result.is_null() {
        anyhow::bail!("gmtime_r failed for current UNIX timestamp");
    }

    Ok(Iso8601TimeParts::new(
        (now.tm_year + 1900) as u16,
        (now.tm_mon + 1) as u8,
        now.tm_mday as u8,
        now.tm_hour as u8,
        now.tm_min as u8,
        now.tm_sec as u8,
    ))
}

pub fn open_current_time_maps()
-> anyhow::Result<(Array<MapData, u64>, Array<MapData, Iso8601TimeParts>)> {
    Ok((
        open_pinned_array("CURRENT_TIME")?,
        open_pinned_array("CURRENT_TIME_ISO8601")?,
    ))
}

pub fn write_current_time(
    current_time: &mut Array<MapData, u64>,
    current_time_iso8601: &mut Array<MapData, Iso8601TimeParts>,
) -> anyhow::Result<()> {
    current_time
        .set(0, current_unix_timestamp()?, 0)
        .context("failed to write CURRENT_TIME[0]")?;
    current_time_iso8601
        .set(0, current_iso8601_time_parts()?, 0)
        .context("failed to write CURRENT_TIME_ISO8601[0]")?;
    Ok(())
}

pub async fn run_current_time_updater(
    current_time: &mut Array<MapData, u64>,
    current_time_iso8601: &mut Array<MapData, Iso8601TimeParts>,
) -> anyhow::Result<()> {
    let mut ticker = time::interval(Duration::from_secs(1));

    write_current_time(current_time, current_time_iso8601)?;

    loop {
        ticker.tick().await;
        write_current_time(current_time, current_time_iso8601)?;
    }
}

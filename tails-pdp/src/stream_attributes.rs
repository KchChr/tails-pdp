use std::{
    env, fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, bail};
use aya::maps::{Array, MapData};
use log::{info, warn};
use tails_pdp_common::{DEFAULT_DEFCON_LEVEL, DEFCON_MAX_LEVEL, DEFCON_MIN_LEVEL};
use tokio::time::{Duration, sleep};

use crate::fs_watch;

const STREAM_ATTRIBUTES_DIRECTORY_NAME: &str = "environment";
const DEFCON_FILE_NAME: &str = "DEFCON.txt";
const STREAM_ATTRIBUTE_EVENT_DEBOUNCE: Duration = Duration::from_millis(100);

pub fn default_stream_attributes_directory() -> anyhow::Result<PathBuf> {
    Ok(env::current_dir()
        .context("failed to determine current working directory")?
        .join(STREAM_ATTRIBUTES_DIRECTORY_NAME))
}

pub fn open_current_defcon_map(ebpf: &mut aya::Ebpf) -> anyhow::Result<Array<MapData, u32>> {
    Array::try_from(
        ebpf.take_map("CURRENT_DEFCON")
            .context("map 'CURRENT_DEFCON' not found")?,
    )
    .context("failed to open CURRENT_DEFCON")
}

pub fn write_current_defcon(current_defcon: &mut Array<MapData, u32>) -> anyhow::Result<()> {
    let defcon_path = ensure_defcon_file()?;
    let mut last_applied = None;
    apply_defcon_file(&defcon_path, current_defcon, &mut last_applied)
}

pub async fn run_defcon_updater(current_defcon: &mut Array<MapData, u32>) -> anyhow::Result<()> {
    let defcon_path = ensure_defcon_file()?;
    let directory = defcon_path
        .parent()
        .context("DEFCON path has no parent directory")?;
    let mut watcher = fs_watch::watch_directory(directory)?;
    let mut last_applied = None;

    apply_defcon_file(&defcon_path, current_defcon, &mut last_applied)?;

    loop {
        watcher.wait_for_change().await?;
        sleep(STREAM_ATTRIBUTE_EVENT_DEBOUNCE).await;
        apply_defcon_file(&defcon_path, current_defcon, &mut last_applied)?;
    }
}

fn ensure_defcon_file() -> anyhow::Result<PathBuf> {
    let directory = default_stream_attributes_directory()?;
    fs::create_dir_all(&directory).with_context(|| {
        format!(
            "failed to create stream attributes directory '{}'",
            directory.display()
        )
    })?;

    let defcon_path = directory.join(DEFCON_FILE_NAME);
    if !defcon_path.exists() {
        fs::write(&defcon_path, format!("{DEFAULT_DEFCON_LEVEL}\n")).with_context(|| {
            format!(
                "failed to create default DEFCON file '{}'",
                defcon_path.display()
            )
        })?;
    }

    info!(
        "Watching DEFCON stream attribute '{}'",
        defcon_path.display()
    );
    Ok(defcon_path)
}

fn apply_defcon_file(
    defcon_path: &Path,
    current_defcon: &mut Array<MapData, u32>,
    last_applied: &mut Option<u32>,
) -> anyhow::Result<()> {
    match read_defcon_level(defcon_path) {
        Ok(level) if Some(level) != *last_applied => {
            current_defcon
                .set(0, level, 0)
                .context("failed to write CURRENT_DEFCON[0]")?;
            *last_applied = Some(level);
            info!("DEFCON stream attribute set to {level}");
        }
        Ok(_) => {}
        Err(error) => {
            if last_applied.is_none() {
                current_defcon
                    .set(0, DEFAULT_DEFCON_LEVEL, 0)
                    .context("failed to write default CURRENT_DEFCON[0]")?;
                *last_applied = Some(DEFAULT_DEFCON_LEVEL);
            }
            warn!(
                "Ignoring invalid DEFCON stream attribute '{}': {error:#}",
                defcon_path.display()
            );
        }
    }

    Ok(())
}

fn read_defcon_level(defcon_path: &Path) -> anyhow::Result<u32> {
    let raw = fs::read_to_string(defcon_path)
        .with_context(|| format!("failed to read '{}'", defcon_path.display()))?;
    let trimmed = raw.trim();
    let level: u32 = trimmed
        .parse()
        .with_context(|| format!("DEFCON value '{trimmed}' is not an integer"))?;

    if !(DEFCON_MIN_LEVEL..=DEFCON_MAX_LEVEL).contains(&level) {
        bail!("DEFCON value {level} is outside {DEFCON_MIN_LEVEL}..={DEFCON_MAX_LEVEL}");
    }

    Ok(level)
}

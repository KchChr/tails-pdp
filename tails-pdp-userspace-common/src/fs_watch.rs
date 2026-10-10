use std::path::Path;

#[cfg(target_os = "linux")]
mod imp {
    use std::{
        collections::HashMap,
        ffi::CString,
        fs, io,
        os::{
            fd::{AsRawFd, FromRawFd, OwnedFd},
            unix::ffi::OsStrExt,
        },
        path::{Path, PathBuf},
    };

    use anyhow::{Context, bail};
    use tokio::io::unix::AsyncFd;

    const EVENT_BUFFER_SIZE: usize = 16 * 1024;
    const WATCH_MASK: u32 = libc::IN_CREATE
        | libc::IN_DELETE
        | libc::IN_DELETE_SELF
        | libc::IN_MOVED_FROM
        | libc::IN_MOVED_TO
        | libc::IN_MOVE_SELF
        | libc::IN_ONLYDIR;

    pub struct DirectoryWatcher {
        fd: AsyncFd<OwnedFd>,
        recursive: bool,
        watches: HashMap<libc::c_int, PathBuf>,
        root: PathBuf,
        extension: String,
    }

    impl DirectoryWatcher {
        pub fn new(path: &Path, recursive: bool, extension: &str) -> anyhow::Result<Self> {
            let raw_fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
            if raw_fd == -1 {
                return Err(io::Error::last_os_error()).context("inotify_init1 failed");
            }

            let owned_fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
            let mut watcher = Self {
                fd: AsyncFd::new(owned_fd).context("failed to register inotify fd with tokio")?,
                recursive,
                watches: HashMap::new(),
                root: path.to_path_buf(),
                extension: extension.to_owned(),
            };
            watcher.add_directory(path)?;
            if recursive {
                watcher.add_existing_subdirectories(path)?;
            }
            Ok(watcher)
        }

        pub async fn wait_for_change(&mut self) -> anyhow::Result<()> {
            loop {
                let mut guard = self.fd.readable_mut().await?;
                let mut buffer = [0u8; EVENT_BUFFER_SIZE];

                match guard.try_io(|inner| read_events(inner.get_ref().as_raw_fd(), &mut buffer)) {
                    Ok(Ok(bytes_read)) => {
                        drop(guard);
                        if self.process_events(&buffer[..bytes_read])? {
                            return Ok(());
                        }
                    }
                    Ok(Err(error)) => return Err(error).context("failed to read inotify events"),
                    Err(_would_block) => continue,
                }
            }
        }

        fn add_existing_subdirectories(&mut self, root: &Path) -> anyhow::Result<()> {
            let entries = fs::read_dir(root).with_context(|| {
                format!("failed to read watched directory '{}'", root.display())
            })?;
            for entry in entries {
                let entry = entry.with_context(|| {
                    format!("failed to iterate watched directory '{}'", root.display())
                })?;
                let path = entry.path();
                if !path.is_dir() {
                    continue;
                }
                self.add_directory(&path)?;
                self.add_existing_subdirectories(&path)?;
            }
            Ok(())
        }

        fn add_directory(&mut self, path: &Path) -> anyhow::Result<()> {
            let path_c = path_to_cstring(path)?;
            let watch_descriptor = unsafe {
                libc::inotify_add_watch(self.fd.get_ref().as_raw_fd(), path_c.as_ptr(), WATCH_MASK)
            };
            if watch_descriptor == -1 {
                return Err(io::Error::last_os_error())
                    .with_context(|| format!("failed to watch directory '{}'", path.display()));
            }
            self.watches.insert(watch_descriptor, path.to_path_buf());
            Ok(())
        }

        fn rebuild_watches(&mut self) -> anyhow::Result<()> {
            // Overflow may have hidden directory moves/removals. Discard stale
            // watches rather than merely adding watches for currently visible paths.
            for (descriptor, _) in self.watches.drain() {
                unsafe {
                    libc::inotify_rm_watch(self.fd.get_ref().as_raw_fd(), descriptor);
                }
            }
            let root = self.root.clone();
            self.add_directory(&root)?;
            if self.recursive {
                self.add_existing_subdirectories(&root)?;
            }
            Ok(())
        }

        fn process_events(&mut self, buffer: &[u8]) -> anyhow::Result<bool> {
            let mut offset = 0;
            let mut changed = false;
            while offset + std::mem::size_of::<libc::inotify_event>() <= buffer.len() {
                let event = unsafe {
                    std::ptr::read_unaligned(buffer[offset..].as_ptr() as *const libc::inotify_event)
                };
                let name_offset = offset + std::mem::size_of::<libc::inotify_event>();
                let name_end = name_offset + event.len as usize;
                if name_end > buffer.len() {
                    bail!("truncated inotify event");
                }

                let name = event_name(&buffer[name_offset..name_end]);
                let mask = event.mask;
                if mask & libc::IN_Q_OVERFLOW != 0 {
                    self.rebuild_watches()?;
                    changed = true;
                }
                if mask & (libc::IN_DELETE_SELF | libc::IN_MOVE_SELF) != 0
                    && self.watches.get(&event.wd) == Some(&self.root)
                {
                    bail!("watched root was removed or moved: {}", self.root.display());
                }
                if mask & libc::IN_IGNORED != 0 {
                    self.watches.remove(&event.wd);
                }
                // Stop tracking directories moved out of the configured tree.
                // Their watch descriptors otherwise keep reporting unrelated events.
                if mask & libc::IN_ISDIR != 0
                    && mask & (libc::IN_MOVED_FROM | libc::IN_DELETE) != 0
                    && let (Some(parent), Some(name)) = (self.watches.get(&event.wd), name)
                {
                    let removed = parent.join(name);
                    let descriptors: Vec<_> = self
                        .watches
                        .iter()
                        .filter_map(|(descriptor, path)| {
                            path.starts_with(&removed).then_some(*descriptor)
                        })
                        .collect();
                    for descriptor in descriptors {
                        unsafe {
                            libc::inotify_rm_watch(self.fd.get_ref().as_raw_fd(), descriptor);
                        }
                        self.watches.remove(&descriptor);
                    }
                }
                if self.recursive
                    && mask & libc::IN_ISDIR != 0
                    && (mask & (libc::IN_CREATE | libc::IN_MOVED_TO)) != 0
                    && let (Some(parent), Some(name)) = (self.watches.get(&event.wd).cloned(), name)
                {
                    let new_directory = parent.join(name);
                    if new_directory.is_dir() {
                        self.add_directory(&new_directory)?;
                        self.add_existing_subdirectories(&new_directory)?;
                        // A complete file may have been published before its new
                        // parent acquired a watch. Rescan to cover that window.
                        changed = true;
                    }
                }
                // Only publication/removal events cause a reload. Writing a staged
                // file must never expose its intermediate contents to the loaders.
                let is_directory = mask & libc::IN_ISDIR != 0;
                let is_active_file = name.is_some_and(|name| {
                    Path::new(name).extension() == Some(std::ffi::OsStr::new(&self.extension))
                });
                if (is_directory || is_active_file) && mask & relevant_change_mask() != 0 {
                    changed = true;
                }

                offset = name_end;
            }
            Ok(changed)
        }
    }

    fn read_events(fd: libc::c_int, buffer: &mut [u8]) -> io::Result<usize> {
        let result =
            unsafe { libc::read(fd, buffer.as_mut_ptr() as *mut libc::c_void, buffer.len()) };
        if result == -1 {
            Err(io::Error::last_os_error())
        } else {
            Ok(result as usize)
        }
    }

    fn event_name(bytes: &[u8]) -> Option<&std::ffi::OsStr> {
        let end = bytes
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(bytes.len());
        if end == 0 {
            return None;
        }
        Some(std::ffi::OsStr::from_bytes(&bytes[..end]))
    }

    fn path_to_cstring(path: &Path) -> anyhow::Result<CString> {
        CString::new(path.as_os_str().as_bytes())
            .with_context(|| format!("path contains interior NUL byte: '{}'", path.display()))
    }

    const fn relevant_change_mask() -> u32 {
        libc::IN_DELETE | libc::IN_MOVED_FROM | libc::IN_MOVED_TO
    }

    #[cfg(test)]
    mod overflow_tests {
        use super::*;

        #[test]
        fn overflow_rebuilds_recursive_watches_and_requests_reconciliation() {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                let root =
                    std::env::temp_dir().join(format!("tails-pdp-overflow-{}", std::process::id()));
                fs::create_dir(&root).unwrap();
                let mut watcher = DirectoryWatcher::new(&root, true, "attributes").unwrap();
                let original_root_watch = *watcher.watches.keys().next().unwrap();
                fs::create_dir(root.join("subjects")).unwrap();
                let overflow = libc::inotify_event {
                    wd: -1,
                    mask: libc::IN_Q_OVERFLOW,
                    cookie: 0,
                    len: 0,
                };
                let bytes = unsafe {
                    std::slice::from_raw_parts(
                        &overflow as *const _ as *const u8,
                        std::mem::size_of_val(&overflow),
                    )
                };
                assert!(watcher.process_events(bytes).unwrap());
                assert!(!watcher.watches.contains_key(&original_root_watch));
                assert!(
                    watcher
                        .watches
                        .values()
                        .any(|path| path == &root.join("subjects"))
                );
                fs::remove_dir_all(root).unwrap();
            });
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    use std::path::Path;

    pub struct DirectoryWatcher;

    impl DirectoryWatcher {
        pub fn new(_path: &Path, _recursive: bool, _extension: &str) -> anyhow::Result<Self> {
            anyhow::bail!("inotify directory watching is only available on Linux")
        }

        pub async fn wait_for_change(&mut self) -> anyhow::Result<()> {
            anyhow::bail!("inotify directory watching is only available on Linux")
        }
    }
}

pub use imp::DirectoryWatcher;

pub fn watch_directory_recursive(path: &Path, extension: &str) -> anyhow::Result<DirectoryWatcher> {
    DirectoryWatcher::new(path, true, extension)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::{
        fs,
        sync::atomic::{AtomicU64, Ordering},
        time::Duration,
    };

    static NEXT_ID: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(std::path::PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "tails-pdp-watch-{}-{}",
                std::process::id(),
                NEXT_ID.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    #[test]
    fn staging_and_direct_writes_do_not_publish_but_rename_and_delete_do() {
        runtime().block_on(async {
            for extension in ["policy", "attributes"] {
                let directory = TestDirectory::new();
                let mut watcher = watch_directory_recursive(&directory.0, extension).unwrap();
                let staged = directory.0.join("prepared.tmp");
                let active = directory.0.join(format!("active.{extension}"));
                fs::write(&staged, "unfinished").unwrap();
                fs::write(&active, "unsupported direct write").unwrap();
                assert!(
                    tokio::time::timeout(Duration::from_millis(30), watcher.wait_for_change())
                        .await
                        .is_err()
                );
                fs::write(&staged, "complete").unwrap();
                fs::rename(&staged, &active).unwrap();
                tokio::time::timeout(Duration::from_secs(2), watcher.wait_for_change())
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(fs::read_to_string(&active).unwrap(), "complete");
                fs::remove_file(&active).unwrap();
                tokio::time::timeout(Duration::from_secs(2), watcher.wait_for_change())
                    .await
                    .unwrap()
                    .unwrap();
            }
        });
    }

    #[test]
    fn newly_created_and_moved_subdirectories_are_rescanned_and_watched() {
        runtime().block_on(async {
            let directory = TestDirectory::new();
            let external = TestDirectory::new();
            let mut watcher = watch_directory_recursive(&directory.0, "attributes").unwrap();
            let nested = directory.0.join("subjects");
            fs::create_dir(&nested).unwrap();
            fs::write(
                nested.join("1000.attributes"),
                "complete before watch installation",
            )
            .unwrap();
            tokio::time::timeout(Duration::from_secs(2), watcher.wait_for_change())
                .await
                .unwrap()
                .unwrap();
            fs::write(nested.join("next.tmp"), "new complete value").unwrap();
            fs::rename(nested.join("next.tmp"), nested.join("1000.attributes")).unwrap();
            tokio::time::timeout(Duration::from_secs(2), watcher.wait_for_change())
                .await
                .unwrap()
                .unwrap();
            fs::create_dir(external.0.join("resources")).unwrap();
            fs::write(external.0.join("resources/file.attributes"), "complete").unwrap();
            fs::rename(external.0.join("resources"), directory.0.join("resources")).unwrap();
            tokio::time::timeout(Duration::from_secs(2), watcher.wait_for_change())
                .await
                .unwrap()
                .unwrap();
        });
    }

    #[test]
    fn rapid_replacements_eventually_expose_latest_file_and_root_loss_is_an_error() {
        runtime().block_on(async {
            let directory = TestDirectory::new();
            let mut watcher = watch_directory_recursive(&directory.0, "policy").unwrap();
            for contents in ["first", "second", "latest"] {
                fs::write(directory.0.join("prepared.tmp"), contents).unwrap();
                fs::rename(
                    directory.0.join("prepared.tmp"),
                    directory.0.join("active.policy"),
                )
                .unwrap();
            }
            tokio::time::timeout(Duration::from_secs(2), watcher.wait_for_change())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                fs::read_to_string(directory.0.join("active.policy")).unwrap(),
                "latest"
            );
            // Drain removal events first, then observe the invalid root itself.
            fs::remove_file(directory.0.join("active.policy")).unwrap();
            tokio::time::timeout(Duration::from_secs(2), watcher.wait_for_change())
                .await
                .unwrap()
                .unwrap();
            fs::remove_dir(&directory.0).unwrap();
            assert!(
                tokio::time::timeout(Duration::from_secs(2), watcher.wait_for_change())
                    .await
                    .unwrap()
                    .is_err()
            );
        });
    }
}

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
    const WATCH_MASK: u32 = libc::IN_ATTRIB
        | libc::IN_CLOSE_WRITE
        | libc::IN_CREATE
        | libc::IN_DELETE
        | libc::IN_DELETE_SELF
        | libc::IN_MODIFY
        | libc::IN_MOVED_FROM
        | libc::IN_MOVED_TO
        | libc::IN_MOVE_SELF
        | libc::IN_ONLYDIR;

    pub struct DirectoryWatcher {
        fd: AsyncFd<OwnedFd>,
        recursive: bool,
        watches: HashMap<libc::c_int, PathBuf>,
    }

    impl DirectoryWatcher {
        pub fn new(path: &Path, recursive: bool) -> anyhow::Result<Self> {
            let raw_fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
            if raw_fd == -1 {
                return Err(io::Error::last_os_error()).context("inotify_init1 failed");
            }

            let owned_fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
            let mut watcher = Self {
                fd: AsyncFd::new(owned_fd).context("failed to register inotify fd with tokio")?,
                recursive,
                watches: HashMap::new(),
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
                    changed = true;
                }
                if mask & libc::IN_IGNORED != 0 {
                    self.watches.remove(&event.wd);
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
                    }
                }
                if mask & relevant_change_mask() != 0 {
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
        libc::IN_ATTRIB
            | libc::IN_CLOSE_WRITE
            | libc::IN_CREATE
            | libc::IN_DELETE
            | libc::IN_DELETE_SELF
            | libc::IN_MODIFY
            | libc::IN_MOVED_FROM
            | libc::IN_MOVED_TO
            | libc::IN_MOVE_SELF
            | libc::IN_Q_OVERFLOW
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    use std::path::Path;

    pub struct DirectoryWatcher;

    impl DirectoryWatcher {
        pub fn new(_path: &Path, _recursive: bool) -> anyhow::Result<Self> {
            anyhow::bail!("inotify directory watching is only available on Linux")
        }

        pub async fn wait_for_change(&mut self) -> anyhow::Result<()> {
            anyhow::bail!("inotify directory watching is only available on Linux")
        }
    }
}

pub use imp::DirectoryWatcher;

pub fn watch_directory_recursive(path: &Path) -> anyhow::Result<DirectoryWatcher> {
    DirectoryWatcher::new(path, true)
}

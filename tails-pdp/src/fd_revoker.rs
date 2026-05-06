use anyhow::{Context, bail};

pub fn close_remote_fd(pid: u32, fd: i32) -> anyhow::Result<()> {
    close_remote_fd_impl(pid, fd)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn close_remote_fd_impl(pid: u32, fd: i32) -> anyhow::Result<()> {
    if fd < 0 {
        bail!("invalid negative fd {fd}");
    }
    if pid == 0 || pid == 1 || pid == std::process::id() {
        bail!("refusing to close fd {fd} in protected pid {pid}");
    }

    let mut process = TracedProcess::attach(pid as libc::pid_t)?;
    process.close_fd(fd)
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn close_remote_fd_impl(_pid: u32, _fd: i32) -> anyhow::Result<()> {
    bail!("remote fd close is only implemented for x86_64 Linux")
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
struct TracedProcess {
    pid: libc::pid_t,
    detached: bool,
}

#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "musl"))]
type PtraceRequest = libc::c_int;

#[cfg(all(target_os = "linux", target_arch = "x86_64", not(target_env = "musl")))]
type PtraceRequest = libc::c_uint;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl TracedProcess {
    fn attach(pid: libc::pid_t) -> anyhow::Result<Self> {
        ptrace_simple(libc::PTRACE_ATTACH, pid).context("PTRACE_ATTACH failed")?;
        wait_stopped(pid).context("target did not stop after PTRACE_ATTACH")?;
        Ok(Self {
            pid,
            detached: false,
        })
    }

    fn close_fd(&mut self, fd: i32) -> anyhow::Result<()> {
        let original_regs = ptrace_getregs(self.pid).context("PTRACE_GETREGS failed")?;
        let original_word =
            ptrace_peek_text(self.pid, original_regs.rip).context("PTRACE_PEEKTEXT failed")?;
        let patched_word = syscall_trap_word(original_word);

        ptrace_poke_text(self.pid, original_regs.rip, patched_word)
            .context("failed to patch target instruction with syscall")?;

        let syscall_result = self.run_close_syscall(fd, original_regs);
        let restore_text_result = ptrace_poke_text(self.pid, original_regs.rip, original_word)
            .context("failed to restore target instruction");
        let restore_regs_result =
            ptrace_setregs(self.pid, &original_regs).context("failed to restore target registers");

        restore_text_result?;
        restore_regs_result?;
        syscall_result
    }

    fn run_close_syscall(
        &self,
        fd: i32,
        original_regs: libc::user_regs_struct,
    ) -> anyhow::Result<()> {
        let mut regs = original_regs;
        regs.rax = libc::SYS_close as u64;
        regs.orig_rax = libc::SYS_close as u64;
        regs.rdi = fd as u64;
        regs.rip = original_regs.rip;

        ptrace_setregs(self.pid, &regs).context("failed to prepare close syscall registers")?;
        ptrace_simple(libc::PTRACE_SINGLESTEP, self.pid)
            .context("PTRACE_SINGLESTEP close syscall failed")?;
        wait_stopped(self.pid).context("target did not stop after close syscall")?;

        let after = ptrace_getregs(self.pid).context("failed to read close syscall result")?;
        close_result(after.rax)
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl Drop for TracedProcess {
    fn drop(&mut self) {
        if !self.detached {
            let _ = unsafe {
                libc::ptrace(
                    libc::PTRACE_DETACH,
                    self.pid,
                    std::ptr::null_mut::<libc::c_void>(),
                    std::ptr::null_mut::<libc::c_void>(),
                )
            };
            self.detached = true;
        }
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn ptrace_simple(request: PtraceRequest, pid: libc::pid_t) -> std::io::Result<()> {
    let result = unsafe {
        libc::ptrace(
            request,
            pid,
            std::ptr::null_mut::<libc::c_void>(),
            std::ptr::null_mut::<libc::c_void>(),
        )
    };
    if result == -1 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn ptrace_getregs(pid: libc::pid_t) -> std::io::Result<libc::user_regs_struct> {
    let mut regs = std::mem::MaybeUninit::<libc::user_regs_struct>::uninit();
    let result = unsafe {
        libc::ptrace(
            libc::PTRACE_GETREGS,
            pid,
            std::ptr::null_mut::<libc::c_void>(),
            regs.as_mut_ptr(),
        )
    };
    if result == -1 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(unsafe { regs.assume_init() })
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn ptrace_setregs(pid: libc::pid_t, regs: &libc::user_regs_struct) -> std::io::Result<()> {
    let result = unsafe {
        libc::ptrace(
            libc::PTRACE_SETREGS,
            pid,
            std::ptr::null_mut::<libc::c_void>(),
            regs as *const _ as *mut libc::c_void,
        )
    };
    if result == -1 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn ptrace_peek_text(pid: libc::pid_t, address: u64) -> std::io::Result<libc::c_long> {
    unsafe {
        *libc::__errno_location() = 0;
    }
    let result = unsafe {
        libc::ptrace(
            libc::PTRACE_PEEKTEXT,
            pid,
            address as usize as *mut libc::c_void,
            std::ptr::null_mut::<libc::c_void>(),
        )
    };
    let error = std::io::Error::last_os_error();
    if result == -1 && error.raw_os_error().unwrap_or(0) != 0 {
        Err(error)
    } else {
        Ok(result)
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn ptrace_poke_text(pid: libc::pid_t, address: u64, word: libc::c_long) -> std::io::Result<()> {
    let result = unsafe {
        libc::ptrace(
            libc::PTRACE_POKETEXT,
            pid,
            address as usize as *mut libc::c_void,
            word as usize as *mut libc::c_void,
        )
    };
    if result == -1 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn wait_stopped(pid: libc::pid_t) -> std::io::Result<()> {
    let mut status = 0;
    let result = unsafe { libc::waitpid(pid, &mut status, 0) };
    if result == -1 {
        return Err(std::io::Error::last_os_error());
    }
    if !libc::WIFSTOPPED(status) {
        return Err(std::io::Error::other(format!(
            "unexpected wait status {status}"
        )));
    }
    Ok(())
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn syscall_trap_word(original_word: libc::c_long) -> libc::c_long {
    let mut bytes = original_word.to_ne_bytes();
    bytes[0] = 0x0f;
    bytes[1] = 0x05;
    bytes[2] = 0xcc;
    libc::c_long::from_ne_bytes(bytes)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn close_result(rax: u64) -> anyhow::Result<()> {
    let value = rax as i64;
    if value < 0 && value >= -4095 {
        let errno = -value as i32;
        if errno == libc::EBADF {
            return Ok(());
        }
        return Err(std::io::Error::from_raw_os_error(errno))
            .context("remote close syscall failed");
    }
    Ok(())
}

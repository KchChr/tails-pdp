#!/usr/bin/env python3
"""E2E-17: syscall coordination or high-resolution measurement helper."""
from support import *


def ptrace_failure(r):
    blocked, blocked_dir = r.probe()
    libc = ctypes.CDLL(None, use_errno=True)
    # PTRACE_SEIZE: make the test driver the tracer; a second attach must fail.
    assert libc.ptrace(0x4206, blocked.pid, None, None) == 0, os.strerror(ctypes.get_errno())
    healthy, healthy_dir = r.probe()
    offset = len(r.log())
    r.policy(command="tails-fd-probe")
    r.wait(lambda: f"failed to close pid={blocked.pid}" in r.log()[offset:], "ptrace failure log")
    result = r.results(healthy, healthy_dir)[0]
    assert all(result["closed"]) and all(result["safe_open"]), result
    (blocked_dir / "stop").touch()
    blocked_result = r.results(blocked, blocked_dir)[0]
    assert not any(blocked_result["closed"]), blocked_result
    r.alive()
    r.remove()
    r.policy()  # Further activation and kernel enforcement still work.
    r.expect(False)
    return {"blocked": blocked_result, "healthy": result}

if __name__ == "__main__":
    execute_python(ptrace_failure)

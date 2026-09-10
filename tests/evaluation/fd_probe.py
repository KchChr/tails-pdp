#!/usr/bin/env python3
"""Real child process for FD, inheritance, mmap and race characterization."""
import ctypes
import errno
import json
import mmap
import os
from pathlib import Path
import sys
import time

mode, target, safe, directory = sys.argv[1:]
root = Path(directory)
libc = ctypes.CDLL(None, use_errno=True)
# Fixed, explicit comm avoids differences between Python executable names.
assert libc.prctl(15, b"tails-fd-probe", 0, 0, 0) == 0
fds = [os.open(target, os.O_RDONLY) for _ in range(3)]
safe_fds = [os.open(safe, os.O_RDONLY) for _ in range(2)]
mapping = None
if mode == "char":
    fds.append(os.dup(fds[0]))
    mapping = mmap.mmap(fds[0], 0, access=mmap.ACCESS_READ)
    child = os.fork()
    if child == 0:
        mode = "inherited"
(root / f"ready-{os.getpid()}.json").write_text(json.dumps({"pid": os.getpid(), "fds": fds, "safe": safe_fds}))

def closed(fd):
    try:
        os.fstat(fd)
        return False
    except OSError as error:
        if error.errno != errno.EBADF:
            raise
        return True

deadline = time.monotonic() + 45
result = None
if mode == "race":
    # Reuse one descriptor number, alternating actual resources. Only this thread
    # touches slot 100; EBADF after installing the safe file is an unintended close.
    slot = 100
    safe_identity = os.stat(safe).st_ino
    iterations = 0
    wrong_closes = 0
    while not (root / "stop").exists() and time.monotonic() < deadline:
        try:
            source = os.open(target, os.O_RDONLY)
        except PermissionError:
            source = None
        if source is not None:
            os.dup2(source, slot)
            os.close(source)
            time.sleep(0.0002)
        safe_source = os.open(safe, os.O_RDONLY)
        os.dup2(safe_source, slot)
        os.close(safe_source)
        time.sleep(0.0005)
        if closed(slot):
            wrong_closes += 1
        else:
            assert os.fstat(slot).st_ino == safe_identity
        iterations += 1
    result = {"iterations": iterations, "wrong_safe_closes": wrong_closes}
else:
    while time.monotonic() < deadline:
        state = [closed(fd) for fd in fds]
        safe_state = [not closed(fd) for fd in safe_fds]
        if all(state) or not all(safe_state) or (root / "stop").exists():
            result = {"closed": state, "safe_open": safe_state, "observed_ns": time.monotonic_ns()}
            if mapping is not None:
                result["mmap_readable"] = bool(mapping[:1])
            break
        time.sleep(0.001)
if result is None:
    result = {"timeout": True, "closed": [closed(fd) for fd in fds]}
(root / f"result-{os.getpid()}.json").write_text(json.dumps(result))
if mode == "char":
    os.waitpid(child, 0)

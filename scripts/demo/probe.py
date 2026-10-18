#!/usr/bin/env python3
"""Syscall helpers for the Bash demo; no external Python dependencies."""
import ctypes
import errno
import json
import os
from pathlib import Path
import sys
import time


def set_command(name):
    if ctypes.CDLL(None, use_errno=True).prctl(15, name.encode(), 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "prctl(PR_SET_NAME)")


def is_open(fd):
    try:
        os.fstat(fd)
        return True
    except OSError as error:
        if error.errno != errno.EBADF:
            raise
        return False


def save(path, value):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value))
    temporary.replace(path)


def access(path, command, uid):
    set_command(command)
    # Exercise real-UID matching without creating accounts or changing DAC rights.
    if uid != "-":
        os.setresuid(int(uid), 0, 0)
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError as error:
        if error.errno != errno.EPERM:
            raise
        print("deny")
    else:
        os.close(fd)
        print("allow")


def hold(target, safe, directory):
    def message(text):
        print(f"{os.environ.get('DEMO_OUTPUT_COLOR', '')}[FD-Beobachter: probe.py hold] {text}{os.environ.get('DEMO_COLOR_RESET', '')}", flush=True)

    set_command("tails-demo-fd")
    root = Path(directory)
    protected = [os.open(target, os.O_RDONLY) for _ in range(3)]
    controls = [os.open(safe, os.O_RDONLY) for _ in range(2)]
    message(f"PID {os.getpid()}: drei geschützte FDs {protected}, zwei Kontroll-FDs {controls} geöffnet.")
    save(root / "ready.json", {"pid": os.getpid(), "protected": protected, "controls": controls})
    previous = None
    while True:
        opened = [is_open(fd) for fd in protected]
        safe_open = [is_open(fd) for fd in controls]
        state = (opened, safe_open)
        if state != previous:
            message(f"Geschützte FDs offen: {opened} | Kontroll-FDs offen: {safe_open} | Prozess läuft")
            save(root / "state.json", {"protected": opened, "controls": safe_open, "unix_ns": time.time_ns()})
            previous = state
        # Stay alive after revocation to demonstrate that the process is not killed.
        time.sleep(0.05)


if __name__ == "__main__":
    if sys.argv[1] == "access":
        access(*sys.argv[2:])
    elif sys.argv[1] == "hold":
        hold(*sys.argv[2:])
    else:
        raise SystemExit("unknown probe mode")

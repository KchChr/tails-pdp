#!/usr/bin/env python3
"""Privileged evaluation scenarios. Each owns a fresh runtime and preserves artifacts.

Run via sudo python3 tests/evaluation/run.py [IDs ...]. No third-party Python packages.
Failures are reported as FAIL, never converted into successful characterization.
"""
import argparse
import ctypes
import errno
import fcntl
import json
import math
import os
from pathlib import Path
import platform
import re
import signal
import statistics
import subprocess
import sys
import tempfile
import time
import traceback

PROJECT = Path(__file__).resolve().parents[2]
PIN = Path("/sys/fs/bpf/tails-pdp")
MAPS = ["POLICY_GENERATION", "ATTRIBUTE_GENERATION", "FILE_OPEN_STATIC_POLICIES",
        "FILE_OPEN_STREAM_POLICIES", "CURRENT_TIME", "ATTRIBUTES"]
TIMEOUT = float(os.environ.get("EVAL_TIMEOUT", "20"))
REPEATS = int(os.environ.get("EVAL_REPEATS", "10"))
STAB_CYCLES = int(os.environ.get("EVAL_STAB_CYCLES", "100"))



def atomic(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text)
    stamp = time.monotonic_ns()
    tmp.replace(path)
    return stamp


def stats(samples):
    ordered = sorted(samples)
    assert ordered
    return {"n": len(samples), "median": statistics.median(samples),
            "p95": ordered[math.ceil(len(ordered) * .95) - 1],
            "p99": ordered[math.ceil(len(ordered) * .99) - 1],
            "min": min(samples), "max": max(samples), "samples": samples}


class Runtime:
    def __init__(self, root):
        self.root = root
        root.mkdir()
        self.policies = root / "policies"
        self.attrs = root / "attributes"
        self.policies.mkdir()
        self.attrs.mkdir()
        self.target = root / "target"
        self.safe = root / "safe"
        self.target.write_text("protected\n")
        self.safe.write_text("safe\n")
        atomic(self.attrs / "system.attributes", "defcon = 5\n")
        self.logpath = root / "runtime.log"
        self.proc = None
        self.owns_runtime = True
        self.helpers = []
        self.runtime_bin = os.environ.get("TAILS_PDP_BIN", str(PROJECT / "target/release/tails-pdp"))
        self.admin_bin = os.environ.get("ADM_TOOL_BIN", str(PROJECT / "target/release/tails-pdp-admintool"))

    def start(self):
        assert not subprocess.run(["pgrep", "-x", "tails-pdp"], capture_output=True).stdout, "another runtime is active"
        self.logfile = self.logpath.open("w")
        self.proc = subprocess.Popen([self.runtime_bin], cwd=self.root, stdout=self.logfile,
            stderr=subprocess.STDOUT, env={**os.environ, "RUST_LOG": "info", "TAILS_PDP_EBPF_DEBUG": "0"})
        self.wait(lambda: "Waiting for Ctrl-C" in self.log(), "runtime attach")
        assert all((PIN / name).exists() for name in MAPS)
        self.wait(lambda: "scan completed" in self.log(), "initial scan")

    def alive(self):
        assert self.proc.poll() is None, f"runtime exited {self.proc.returncode}: {self.log()[-1800:]}"

    def wait(self, predicate, label):
        deadline = time.monotonic() + TIMEOUT
        while time.monotonic() < deadline:
            self.alive()
            value = predicate()
            if value:
                return value
            time.sleep(.01)
        raise AssertionError(f"timeout: {label}")

    def log(self):
        return self.logpath.read_text(errors="replace") if self.logpath.exists() else ""

    def admin(self, command="show-active"):
        return subprocess.check_output([self.admin_bin, "--policy-dir", str(self.policies),
            "--attributes-dir", str(self.attrs), command], text=True, timeout=5)

    def generations(self):
        match = re.search(r"generation policy=(\d+).*attribute=(\d+)", self.admin())
        assert match, "missing generation output"
        return tuple(map(int, match.groups()))

    def changed(self, before, kind):
        self.wait(lambda: self.generations()[kind] != before[kind], "generation activation")

    def policy_text(self, name="test", effect="deny", conditions="", command=""):
        return (f'policy "{name}"\n{effect}\n action == "file_open";\n'
                f' resource.path == "{self.target}";\n' +
                (f' command == "{command}";\n' if command else "") + conditions + "\n")

    def policy(self, conditions="", effect="deny", name="test", command=""):
        before = self.generations()
        stamp = atomic(self.policies / f"{name}.policy", self.policy_text(name, effect, conditions, command))
        self.changed(before, 0)
        return stamp

    def attribute(self, relative, text):
        before = self.generations()
        stamp = atomic(self.attrs / relative, text)
        self.changed(before, 1)
        return stamp

    def access(self):
        # Only EPERM counts as policy denial; ENOENT/EIO/etc. are test failures.
        try:
            fd = os.open(self.target, os.O_RDONLY)
        except OSError as error:
            if error.errno == errno.EPERM:
                return False
            raise
        os.close(fd)
        return True

    def expect(self, allow):
        self.wait(lambda: self.access() == allow, f"access={allow}")

    def remove(self, name="test"):
        before = self.generations()
        (self.policies / f"{name}.policy").unlink()
        self.changed(before, 0)

    def probe(self, mode="multi"):
        directory = self.root / f"probe-{len(self.helpers)}"
        directory.mkdir()
        process = subprocess.Popen([sys.executable, str(Path(__file__).with_name("fd_probe.py")),
            mode, str(self.target), str(self.safe), str(directory)], start_new_session=True,
            stdout=subprocess.DEVNULL, stderr=(directory / "stderr.log").open("w"))
        self.helpers.append(process)
        count = 2 if mode == "char" else 1
        self.wait(lambda: len(list(directory.glob("ready-*.json"))) == count, "probe ready")
        return process, directory

    def results(self, process, directory, count=1):
        self.wait(lambda: len(list(directory.glob("result-*.json"))) == count, "probe results")
        process.wait(timeout=5)
        assert process.returncode == 0
        return [json.loads(p.read_text()) for p in directory.glob("result-*.json")]

    def close(self):
        for process in self.helpers:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
        if self.proc is not None and self.owns_runtime:
            self.proc.send_signal(signal.SIGINT) if self.proc.poll() is None else None
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
            self.logfile.close()
            for name in MAPS:
                (PIN / name).unlink(missing_ok=True)

class ExistingProcess:
    def __init__(self, pid):
        self.pid = pid
        self.returncode = None
    def poll(self):
        try:
            state = Path(f"/proc/{self.pid}/stat").read_text().rsplit(") ", 1)[1][0]
            if state == "Z":
                self.returncode = 1
                return 1
            return None
        except FileNotFoundError:
            self.returncode = 1
            return 1


def execute_python(function):
    """Run only a syscall/measurement helper inside the Bash scenario's fixture."""
    root = Path(os.environ["TEST_ROOT"])
    runtime = Runtime.__new__(Runtime)
    runtime.root = root
    runtime.policies = root / "policies"
    runtime.attrs = root / "attributes"
    runtime.target = root / "target"
    runtime.safe = root / "safe"
    runtime.logpath = root / "runtime.log"
    runtime.helpers = []
    runtime.runtime_bin = os.environ["TAILS_PDP_BIN"]
    runtime.admin_bin = os.environ["ADM_TOOL_BIN"]
    pid = os.environ.get("RUNTIME_PID", "")
    runtime.proc = ExistingProcess(int(pid)) if pid else None
    runtime.owns_runtime = not bool(pid)
    try:
        detail = function(runtime)
        (root / "detail.json").write_text(json.dumps(detail, indent=2))
    finally:
        runtime.close()

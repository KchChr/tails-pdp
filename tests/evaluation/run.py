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
        if self.proc is not None:
            self.proc.send_signal(signal.SIGINT) if self.proc.poll() is None else None
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
            self.logfile.close()
            for name in MAPS:
                (PIN / name).unlink(missing_ok=True)


def combining(r):
    r.policy(effect="permit", name="permit")
    r.expect(True)
    r.policy(name="deny")
    r.expect(False)
    r.remove("deny")
    r.expect(True)
    # Reverse insertion/order: deny must win in either policy order.
    r.policy(name="aaa-deny")
    r.expect(False)


def conjunction(r):
    subject = f"subjects/{os.getuid()}.attributes"
    resource = f"resources{r.target}.attributes"
    r.attribute("system.attributes", "defcon = 2\n")
    r.attribute(subject, 'position = "engineer"\n')
    r.attribute(resource, 'classification = "internal"\n')
    r.policy('system.defcon <= 2;\nsubject.position == "engineer";\nresource.classification == "internal";')
    r.expect(False)
    for path, bad, good in [("system.attributes", "defcon = 5", "defcon = 2"),
        (subject, 'position = "intern"', 'position = "engineer"'),
        (resource, 'classification = "public"', 'classification = "internal"'),
        (subject, 'position = 1', 'position = "engineer"'),
        (subject, '# missing attribute', 'position = "engineer"')]:
        r.attribute(path, bad + "\n")
        r.expect(True)
        r.attribute(path, good + "\n")
        r.expect(False)


def invalid_attributes(r):
    r.attribute("system.attributes", "defcon = 2\n")
    r.policy("system.defcon <= 2;")
    r.expect(False)
    before = r.generations()
    offset = len(r.log())
    atomic(r.attrs / "system.attributes", "defcon = 9\n")
    r.wait(lambda: "Ignoring invalid stream attributes" in r.log()[offset:], "invalid attribute log")
    assert r.generations() == before, "invalid generation activated"
    r.expect(False)
    r.attribute("system.attributes", "defcon = 5\n")
    r.expect(True)


def observable(r):
    r.attribute("system.attributes", "defcon = 2\n")
    r.policy("system.defcon <= 2;")
    r.expect(False)
    output = r.admin()
    (r.root / "admin.txt").write_text(output)
    active_lines = [line for line in output.splitlines() if "enabled=1" in line]
    assert len(active_lines) == 1 and "entitlement=Deny" in active_lines[0]
    assert f'inode={os.stat(r.target).st_ino}' in active_lines[0]
    assert "system.defcon" in output and "attribute_condition=" in output
    assert "system.defcon = 2" in output
    return {"evidence": "single active Deny, resource inode, condition and actual attribute value",
            "limitation": "state inspection; no per-open decision trace or original policy name"}


def admin_variants(r):
    r.attribute("system.attributes", "defcon = 2\n")
    r.policy(name="static")
    r.policy("system.defcon <= 2;", name="stream")
    before = r.generations()
    for command in ["show", "show-policies", "show-attributes"]:
        first = r.admin(command)
        second = r.admin(command)
        (r.root / f"{command}.txt").write_text(first)
        assert first == second, f"unstable output: {command}"
        assert r.generations() == before
        if command != "show-attributes":
            assert first.count("enabled=1") == 2
            assert "FILE_OPEN_STATIC_POLICIES:" in first and "FILE_OPEN_STREAM_POLICIES:" in first
            assert first.count("enabled=0") == 30
        if command != "show-policies":
            assert "ATTRIBUTES:" in first and "system.defcon = 2" in first
        if command == "show-policies":
            assert "ATTRIBUTES:" not in first
        if command == "show-attributes":
            assert "FILE_OPEN_" not in first
        r.expect(False)


def real_uid(r):
    # Numeric real UID needs no persistent account. Effective/fs UID remains root,
    # so DAC cannot explain a denial. A second real UID is the negative control.
    r.policy("subject.uid == 60001;")
    script = '''import os,errno,sys
os.setresuid(int(sys.argv[2]),0,0)
assert os.getuid()!=os.geteuid()
try:
 fd=os.open(sys.argv[1],os.O_RDONLY);os.close(fd);print("allow")
except OSError as e:
 assert e.errno==errno.EPERM;print("deny")
'''
    for uid, expected in [(60001, "deny"), (60002, "allow")]:
        output = subprocess.check_output([sys.executable, "-c", script, str(r.target), str(uid)], text=True)
        assert output.strip() == expected, (uid, output, expected)


def multi_fd(r):
    process, directory = r.probe()
    r.policy(command="tails-fd-probe")
    result = r.results(process, directory)[0]
    assert result.get("closed") == [True] * 3 and result.get("safe_open") == [True] * 2, result
    return result


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


def characterize(r):
    process, directory = r.probe("char")
    r.policy(command="tails-fd-probe")
    results = r.results(process, directory, 2)
    for result in results:
        assert result.get("closed") == [True] * 4 and all(result["safe_open"]), result
        assert result.get("mmap_readable") is True, result
    return {"processes": results, "limitation": "mmap stays readable after descriptor revocation"}


def race(r):
    process, directory = r.probe("race")
    for _ in range(REPEATS):
        r.policy(command="tails-fd-probe")
        r.remove()
    (directory / "stop").touch()
    result = r.results(process, directory)[0]
    assert result.get("iterations", 0) > 100, result
    (r.root / "race-observation.json").write_text(json.dumps(result, indent=2))
    assert result["wrong_safe_closes"] == 0, f"wrong safe descriptor closed: {result}"
    return {**result, "limitation": "stochastic test; zero observations do not prove race freedom"}


def perf_open(r):
    def measure():
        for _ in range(1000):
            fd = os.open(r.target, os.O_RDONLY); os.close(fd)
        samples = []
        for _ in range(20000):
            start = time.perf_counter_ns()
            fd = os.open(r.target, os.O_RDONLY)
            end = time.perf_counter_ns()
            os.close(fd)
            samples.append(end - start)
        return stats(samples)
    baseline = measure()
    r.start()
    empty = measure()
    r.policy(effect="permit")
    permit = measure()
    return {"unit": "ns", "measurement": "warm-cache os.open including Python and timer overhead; close excluded",
        "baseline": baseline, "runtime_empty": empty, "runtime_permit": permit,
        "relative_median_overhead": {"empty": empty["median"] / baseline["median"] - 1,
                                     "permit": permit["median"] / baseline["median"] - 1}}


def perf_changes(r):
    policy_samples = []
    attribute_samples = []
    # Poll the actual new access decision; generation/admin polling is outside timing.
    for _ in range(REPEATS):
        r.expect(True)
        start = atomic(r.policies / "test.policy", r.policy_text())
        r.expect(False)
        policy_samples.append(time.monotonic_ns() - start)
        r.remove()
        r.expect(True)
    r.policy("system.defcon <= 2;")
    for _ in range(REPEATS):
        start = atomic(r.attrs / "system.attributes", "defcon = 2\n")
        r.expect(False)
        attribute_samples.append(time.monotonic_ns() - start)
        r.attribute("system.attributes", "defcon = 5\n")
        r.expect(True)
    return {"unit": "ns", "poll_interval_ms": 10, "policy": stats(policy_samples), "attribute": stats(attribute_samples)}


def perf_revoke(r):
    samples = []
    activation_bounds = []
    for _ in range(REPEATS):
        process, directory = r.probe()
        before = r.generations()
        start = atomic(r.policies / "test.policy", r.policy_text(command="tails-fd-probe"))
        last_old = start
        while True:
            sample_start = time.monotonic_ns()
            generation = r.generations()
            sample_end = time.monotonic_ns()
            if generation[0] != before[0]:
                first_new = sample_end
                break
            last_old = sample_start
            assert sample_end - start < TIMEOUT * 1e9
        result = r.results(process, directory)[0]
        assert all(result["closed"]) and all(result["safe_open"]), result
        observed = result["observed_ns"]
        samples.append(observed - start)
        activation_bounds.append({"lower_ns": max(0, observed - first_new),
            "upper_ns": observed - last_old, "activation_bracket_ns": first_new - last_old})
        r.remove()
    return {"unit": "ns", "file_change_to_EBADF": stats(samples),
        "activation_to_EBADF_bounds": activation_bounds,
        "note": "activation is bracketed by generation reads; no falsely exact activation timestamp; FD poll 1ms"}


def load(r):
    # Both independent 16-entry policy banks, then excess for each kind.
    for kind in ["static", "stream"]:
        condition = "system.defcon <= 2;" if kind == "stream" else ""
        for index in range(16):
            r.policy(condition, effect="permit", name=f"{kind}-{index:02}")
        assert r.admin().count("enabled=1") == (16 if kind == "static" else 32)
        before = r.generations()
        offset = len(r.log())
        overflow = r.policies / "overflow.policy"
        atomic(overflow, r.policy_text("overflow", "permit", condition))
        r.wait(lambda: "previous generation remains active" in r.log()[offset:], "policy capacity rejection")
        assert r.generations() == before
        overflow.unlink()
        time.sleep(.2)
    # ATTRIBUTES has 1024 entries shared between TWO banks. Exercise guaranteed
    # alternating 512-entry generations before trying 513 (1025 total entries).
    for revision in [1, 2, 3]:
        r.attribute("system.attributes", "".join(f"field{i} = {revision}\n" for i in range(512)))
        assert sum(line.startswith("system.field") for line in r.admin().splitlines()) == 512
    before = r.generations()
    offset = len(r.log())
    atomic(r.attrs / "system.attributes", "".join(f"field{i} = 4\n" for i in range(513)))
    # On failure the runtime can briefly deny opens while tearing down its maps.
    # Wait for exit without opening diagnostic files during that interval.
    try:
        r.proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        r.wait(lambda: "failed to write ATTRIBUTES" in r.log()[offset:], "attribute capacity rejection")
    after = r.generations()
    (r.root / "capacity-observation.json").write_text(json.dumps({
        "before": before, "after": after, "runtime_exit": r.proc.poll(),
        "accepted_per_bank": 512, "attempted_new_bank": 513}, indent=2))
    assert after == before
    r.alive()  # A runtime exit is a failure, not a successful rejection.
    return {"static_capacity": 16, "stream_capacity": 16, "attribute_double_bank_capacity": 512}


def stability(r):
    started = time.monotonic()
    for index in range(STAB_CYCLES):
        r.policy(name="test")
        r.expect(False)
        before = r.generations()
        offset = len(r.log())
        atomic(r.policies / "test.policy", f"invalid {index}")
        r.wait(lambda: "previous generation remains active" in r.log()[offset:], "invalid policy")
        assert r.generations() == before
        r.expect(False)
        r.remove()
        r.expect(True)
        invalid_attributes(r)
        r.remove()
    return {"cycles": STAB_CYCLES, "duration_seconds": time.monotonic() - started}


SCENARIOS = {"COMP-04": admin_variants, "E2E-11": combining, "E2E-12": conjunction,
    "E2E-13": invalid_attributes, "E2E-14": observable, "E2E-15": real_uid,
    "E2E-16": multi_fd, "E2E-17": ptrace_failure, "CHAR-01": characterize,
    "RACE-01": race, "PERF-01": perf_open, "PERF-02": perf_changes,
    "PERF-03": perf_revoke, "LOAD-01": load, "STAB-01": stability}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenarios", nargs="*", choices=None)
    args = parser.parse_args()
    selected = args.scenarios or list(SCENARIOS)
    assert set(selected) <= SCENARIOS.keys(), "unknown scenario"
    assert sys.platform == "linux" and os.geteuid() == 0, "requires root on dedicated Linux"
    assert REPEATS >= 2 and STAB_CYCLES >= 1
    assert not subprocess.run(["pgrep", "-x", "tails-pdp"], capture_output=True).stdout, "runtime already running"
    lock = open("/run/lock/tails-pdp-evaluation.lock", "w")
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    # Refuse to delete pre-existing state. Only maps created by this run are removed.
    assert not any((PIN / name).exists() for name in MAPS), "pinned maps already exist; inspect/clean them first"
    root = Path(tempfile.mkdtemp(prefix="tails-eval-", dir="/tmp"))
    print(f"Artifacts: {root}", flush=True)
    report = {"commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=PROJECT, text=True).strip(),
        "kernel": platform.uname()._asdict(), "python": sys.version, "repeats": REPEATS,
        "stability_cycles": STAB_CYCLES, "results": {}}
    for name in selected:
        print(f"==> {name}", flush=True)
        runtime = Runtime(root / name)
        before_kernel = subprocess.run(["dmesg"], capture_output=True, text=True).stdout
        failure = None
        try:
            if name != "PERF-01":
                runtime.start()
            detail = SCENARIOS[name](runtime)
            report["results"][name] = {"status": "PASS", "detail": detail}
        except Exception as error:
            report["results"][name] = {"status": "FAIL", "error": str(error)}
            failure = traceback.format_exc()
        finally:
            runtime.close()
        if failure:
            (runtime.root / "failure.txt").write_text(failure)
        after_kernel = subprocess.run(["dmesg"], capture_output=True, text=True).stdout
        new_kernel = after_kernel[len(before_kernel):] if after_kernel.startswith(before_kernel) else after_kernel
        (runtime.root / "kernel.log").write_text(new_kernel)
        if re.search(r"BUG:|Oops:|Kernel panic|general protection fault", new_kernel):
            report["results"][name] = {"status": "FAIL", "error": "kernel fault; see kernel.log"}
        (root / "report.json").write_text(json.dumps(report, indent=2))
        print(f"{name}: {report['results'][name]['status']}", flush=True)
    print(f"Report: {root / 'report.json'}", flush=True)
    return int(any(item["status"] == "FAIL" for item in report["results"].values()))


if __name__ == "__main__":
    sys.exit(main())

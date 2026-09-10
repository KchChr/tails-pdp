#!/usr/bin/env python3
"""Shared lifecycle/reporting runner; test steps live in the per-ID Bash scripts."""
from support import *

SCENARIOS = {
    "COMP-04": PROJECT / "tests/evaluation/COMP-04.sh",
    "E2E-11": PROJECT / "tests/e2e/E2E-11.sh",
    "E2E-12": PROJECT / "tests/e2e/E2E-12.sh",
    "E2E-13": PROJECT / "tests/e2e/E2E-13.sh",
    "E2E-14": PROJECT / "tests/e2e/E2E-14.sh",
    "E2E-15": PROJECT / "tests/e2e/E2E-15.sh",
    "E2E-16": PROJECT / "tests/e2e/E2E-16.sh",
    "E2E-17": PROJECT / "tests/e2e/E2E-17.sh",
    "CHAR-01": PROJECT / "tests/evaluation/CHAR-01.sh",
    "RACE-01": PROJECT / "tests/evaluation/RACE-01.sh",
    "PERF-01": PROJECT / "tests/evaluation/PERF-01.sh",
    "PERF-02": PROJECT / "tests/evaluation/PERF-02.sh",
    "PERF-03": PROJECT / "tests/evaluation/PERF-03.sh",
    "LOAD-01": PROJECT / "tests/evaluation/LOAD-01.sh",
    "STAB-01": PROJECT / "tests/evaluation/STAB-01.sh",
}

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
    report = {"runner": "bash-scenarios", "commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=PROJECT, text=True).strip(),
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
            script = SCENARIOS[name]
            environment = {**os.environ, "EVAL_CHILD": name, "PROJECT_ROOT": str(PROJECT),
                "TEST_ROOT": str(runtime.root), "POLICY_DIR": str(runtime.policies),
                "ATTRIBUTE_DIR": str(runtime.attrs), "TARGET_FILE": str(runtime.target),
                "SAFE_FILE": str(runtime.safe), "RUNTIME_LOG": str(runtime.logpath),
                "RUNTIME_PID": str(runtime.proc.pid) if runtime.proc else "",
                "TAILS_PDP_BIN": runtime.runtime_bin, "ADM_TOOL_BIN": runtime.admin_bin,
                "BPF_PIN_DIRECTORY": str(PIN), "E2E_TIMEOUT_SECONDS": str(math.ceil(TIMEOUT)),
                "EVAL_REPEATS": str(REPEATS), "EVAL_STAB_CYCLES": str(STAB_CYCLES)}
            with (runtime.root / "scenario.log").open("w") as output:
                result = subprocess.run(["bash", str(script)], env=environment,
                    stdout=output, stderr=subprocess.STDOUT,
                    timeout=max(120, STAB_CYCLES * 10, REPEATS * 60))
            assert result.returncode == 0, f"Bash scenario exited {result.returncode}; see scenario.log"
            detail_path = runtime.root / "detail.json"
            detail = json.loads(detail_path.read_text()) if detail_path.exists() else None
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

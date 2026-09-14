#!/usr/bin/env python3
"""PERF-03: isolated rename -> watcher -> activation -> observed EBADF."""
from support import *


MARKER = re.compile(r"PDP_TIMING event=(\w+) ns=(\d+) generation=(\d+)")


def markers(r):
    return [(name, int(ns), int(gen)) for name, ns, gen in MARKER.findall(r.log())]


def wait_for_quiet(r):
    # A logged Pending watcher state plus completed scans, stable for 300 ms.
    # This is checked again against the first event timestamp after the rename.
    stable_since = None
    previous = None
    deadline = time.monotonic() + TIMEOUT
    while time.monotonic() < deadline:
        r.alive()
        entries = markers(r)
        policy = [e for e in entries if e[0] in ("policy_waiting", "policy_event_received")]
        scans = [e for e in entries if e[0] in ("scan_started", "scan_completed")]
        idle = (policy and policy[-1][0] == "policy_waiting" and scans
                and scans[-1][0] == "scan_completed"
                and sum(e[0] == "scan_started" for e in scans)
                    == sum(e[0] == "scan_completed" for e in scans))
        if idle and entries == previous:
            if stable_since is not None and time.monotonic() - stable_since >= .3:
                return entries
        else:
            stable_since = time.monotonic() if idle else None
        previous = entries
        time.sleep(.01)
    raise AssertionError("no verified quiet watcher/scan state; rebuild with timing support")


def one(entries, name, generation=None):
    found = [ns for event, ns, gen in entries
             if event == name and (generation is None or gen == generation)]
    assert len(found) == 1, f"expected one {name}, got {found}"
    return found[0]


def phase_timestamps(entries, generation, start, observed):
    event = one(entries, "policy_event_received")
    debounce = one(entries, "policy_debounce_completed")
    activate_start = one(entries, "policy_activation_started", generation)
    activate_end = one(entries, "policy_activation_completed", generation)
    assert start <= event <= debounce <= activate_start <= activate_end <= observed
    assert debounce - event >= 100_000_000, "update did not receive a full debounce phase"
    return event, debounce, activate_start, activate_end


def perf_revoke(r):
    samples = []
    activation_bounds = []
    phases = []
    for _ in range(REPEATS):
        process, directory = r.probe()
        # Prepare outside the watched tree, on the same filesystem. Only the
        # final rename generates a policy-directory change during measurement.
        staged = r.root / "staged-policy"
        staged.write_text(r.policy_text(command="tails-fd-probe"))
        before = r.generations()
        quiet = wait_for_quiet(r)
        assert not list(directory.glob("result-*.json")), "probe ended before update"
        r.alive()
        start = time.monotonic_ns()
        staged.replace(r.policies / "test.policy")
        rename_done = time.monotonic_ns()
        result = r.results(process, directory)[0]
        assert result.get("closed") == [True, True, True], result
        assert result.get("safe_open") == [True, True], result
        r.wait(lambda: markers(r)[-1][0] in ("scan_completed", "policy_waiting"), "scan end")
        after = r.generations()
        assert after[0] != before[0] and after[1] == before[1], "unexpected generations"
        entries = markers(r)[len(quiet):]
        observed = result["observed_ns"]
        event, debounce, activate_start, activate_end = phase_timestamps(
            entries, after[0], start, observed)
        samples.append(observed - start)
        activation_bounds.append({"lower_ns": observed - activate_end,
            "upper_ns": observed - activate_start,
            "activation_bracket_ns": activate_end - activate_start})
        phases.append({"quiet_policy_wait_ns": [e[1] for e in quiet if e[0] == "policy_waiting"][-1],
            "rename_start_ns": start, "rename_completed_ns": rename_done,
            "event_received_ns": event, "debounce_completed_ns": debounce,
            "activation_started_ns": activate_start, "activation_completed_ns": activate_end,
            "observed_EBADF_ns": observed, "generations_before": before,
            "generations_after": after, "probe": result})
        r.remove()
    return {"unit": "ns", "clock": "Linux CLOCK_MONOTONIC",
        "file_change_to_EBADF": stats(samples), "activation_to_EBADF_bounds": activation_bounds,
        "phases": phases, "note": "instrumented isolated rename; staging outside watched tree; "
        "Pending watcher and completed scans stable for 300ms; first event follows measurement start; "
        "event timestamp is userspace receipt, activation bracket surrounds map syscall, "
        "EBADF is observed by 1ms FD polling; instrumentation overhead included"}


if __name__ == "__main__":
    execute_python(perf_revoke)

#!/usr/bin/env python3
"""PERF-03: syscall coordination or high-resolution measurement helper."""
from support import *


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

if __name__ == "__main__":
    execute_python(perf_revoke)

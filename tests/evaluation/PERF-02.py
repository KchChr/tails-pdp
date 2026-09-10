#!/usr/bin/env python3
"""PERF-02: syscall coordination or high-resolution measurement helper."""
from support import *


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

if __name__ == "__main__":
    execute_python(perf_changes)

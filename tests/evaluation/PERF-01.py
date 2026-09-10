#!/usr/bin/env python3
"""PERF-01: syscall coordination or high-resolution measurement helper."""
from support import *


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

if __name__ == "__main__":
    execute_python(perf_open)

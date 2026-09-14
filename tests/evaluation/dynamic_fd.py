#!/usr/bin/env python3
"""E2E-18/19: isolate attribute and clock triggers for real FD revocation."""
import json
from pathlib import Path
import sys
import time

from support import execute_python


def source_snapshot(directory):
    return {str(p.relative_to(directory)): (p.read_bytes(), p.stat().st_mtime_ns)
            for p in directory.rglob("*") if p.is_file()}


def install_inactive_deny(r, conditions):
    offset = len(r.log())
    r.policy(conditions=conditions, command="tails-fd-probe")
    generations = r.generations()
    completed = (f"scan completed policy_generation={generations[0]} "
                 f"attribute_generation={generations[1]}")
    r.wait(lambda: completed in r.log()[offset:], "initial policy scan completed")
    return generations


def assert_probe_open(r, process, directory):
    r.alive()
    assert process.poll() is None, "probe exited before trigger"
    assert not list(directory.glob("result-*.json")), "probe completed before trigger"
    ready = json.loads((directory / f"ready-{process.pid}.json").read_text())
    # Check identities as well as existence: a reused FD must not pass this check.
    for key, path in (("fds", r.target), ("safe", r.safe)):
        expected = path.stat()
        for fd in ready[key]:
            actual = Path(f"/proc/{process.pid}/fd/{fd}").stat()
            assert (actual.st_dev, actual.st_ino) == (expected.st_dev, expected.st_ino)


def observe_allowed(r, process, directory, seconds=0.3):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        assert_probe_open(r, process, directory)
        time.sleep(0.01)


def revoked(r, process, directory, offset, cause, generations):
    result = r.results(process, directory)[0]
    assert result.get("closed") == [True, True, True], result
    assert result.get("safe_open") == [True, True], result
    started = (f"scan started cause=[{cause}] policy_generation={generations[0]} "
               f"attribute_generation={generations[1]}")
    assert started in r.log()[offset:], f"missing isolated trigger: {started}"
    completed = (f"scan completed policy_generation={generations[0]} "
                 f"attribute_generation={generations[1]}")
    r.wait(lambda: completed in r.log()[offset:], "revocation scan completed")
    r.alive()
    return result


def attribute_revocation(r):
    before = install_inactive_deny(r, "system.defcon <= 2;")
    policy_sources = source_snapshot(r.policies)
    process, directory = r.probe()
    observe_allowed(r, process, directory)
    assert r.generations() == before, "unexpected activation before attribute change"
    offset = len(r.log())
    changed_ns = r.attribute("system.attributes", "defcon = 2\n")
    after = r.generations()
    assert after[0] == before[0], "policy changed during attribute-only scenario"
    assert after[1] != before[1], "attribute generation did not change"
    result = revoked(r, process, directory, offset, f"attributes:{after[1]}", after)
    assert result["observed_ns"] >= changed_ns, "FD closed before attribute change"
    assert r.generations() == after, "unexpected additional activation"
    assert source_snapshot(r.policies) == policy_sources, "policy sources changed"
    return {"trigger": "attribute-only", "generations_before": before,
            "generations_after": after, "attribute_change_ns": changed_ns, "probe": result}


def time_revocation(r):
    # A large modulus gives one nearby false -> true boundary, without changing
    # the clock or waiting for an hour transition. Deny remains true afterwards.
    modulo = 1 << 32
    boundary = int(time.time()) + 10
    assert boundary < modulo, "test epoch exceeds chosen modulo"
    before = install_inactive_deny(r, f"environment.time % {modulo} >= {boundary};")
    policy_sources = source_snapshot(r.policies)
    attribute_sources = source_snapshot(r.attrs)
    process, directory = r.probe()
    observe_allowed(r, process, directory)
    assert time.time() < boundary - 2, "setup too slow to establish pre-boundary state"
    assert r.generations() == before
    offset = len(r.log())
    # No source writes or map writes by the test after this point.
    result = revoked(r, process, directory, offset, f"time:{boundary}", before)
    assert result["observed_unix_ns"] >= boundary * 1_000_000_000, "premature time revocation"
    assert r.generations() == before, "activation confounded time-only scenario"
    assert source_snapshot(r.policies) == policy_sources, "policy sources changed"
    assert source_snapshot(r.attrs) == attribute_sources, "attribute sources changed"
    return {"trigger": "time-only", "boundary_unix_seconds": boundary,
            "generations_before": before, "generations_after": r.generations(), "probe": result}


if __name__ == "__main__":
    execute_python({"attribute": attribute_revocation, "time": time_revocation}[sys.argv[1]])

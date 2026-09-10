#!/usr/bin/env python3
"""Small syscall helper: EPERM-aware open and optional real/effective UID split."""
import errno
import os
import sys

if len(sys.argv) == 3:
    os.setresuid(int(sys.argv[2]), 0, 0)
    assert os.getuid() != os.geteuid()
try:
    fd = os.open(sys.argv[1], os.O_RDONLY)
except OSError as error:
    if error.errno != errno.EPERM:
        raise
    print("deny")
else:
    os.close(fd)
    print("allow")

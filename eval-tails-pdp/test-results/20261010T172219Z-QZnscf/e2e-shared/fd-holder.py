import errno
import os
import pathlib
import sys
import time

target_path, safe_path, ready_path, result_path = sys.argv[1:]
target_fd = os.open(target_path, os.O_RDONLY)
safe_fd = os.open(safe_path, os.O_RDONLY)
pathlib.Path(ready_path).write_text("ready\n")

deadline = time.monotonic() + 20
while time.monotonic() < deadline:
    try:
        os.fstat(target_fd)
        target_closed = False
    except OSError as error:
        if error.errno != errno.EBADF:
            raise
        target_closed = True

    try:
        os.fstat(safe_fd)
        safe_open = True
    except OSError:
        safe_open = False

    if target_closed:
        pathlib.Path(result_path).write_text(
            f"target_closed={target_closed} safe_open={safe_open}\n"
        )
        sys.exit(0 if safe_open else 2)
    time.sleep(0.1)

pathlib.Path(result_path).write_text("timeout\n")
sys.exit(3)

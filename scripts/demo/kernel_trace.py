#!/usr/bin/env python3
"""Forward selected prototype bpf_printk messages into the demo runtime pane."""
import argparse
import os
from pathlib import Path
import re
import select
import signal
import time


DECISION = re.compile(r'(?:^|:\s+)file_open (?:final=deny|tail_call=failed stage=(?:static|stream|combine))\s*$')


def selected(line):
    """Keep final denials and fail-closed tail-call failures, not every open."""
    return bool(DECISION.search(line))


def forward(pipe_path, ready_path, archive_path):
    stopped = False

    def stop(_signal, _frame):
        nonlocal stopped
        stopped = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    descriptor = os.open(pipe_path, os.O_RDONLY | os.O_NONBLOCK)
    color = os.environ.get('DEMO_OUTPUT_COLOR', '')
    reset = os.environ.get('DEMO_COLOR_RESET', '')
    try:
        # trace_pipe can contain entries from earlier runs. Consume that backlog
        # before signalling readiness, while the demo runtime is still stopped.
        deadline = time.monotonic() + 2
        while not stopped and time.monotonic() < deadline:
            try:
                if not os.read(descriptor, 65536):
                    raise RuntimeError('Kernel-Trace wurde geschlossen')
            except BlockingIOError:
                break
        if stopped:
            return
        Path(ready_path).write_text('ready\n')
        pending = b''
        with open(archive_path, 'a', encoding='utf-8', buffering=1) as archive:
            while not stopped:
                if not select.select([descriptor], [], [], 0.2)[0]:
                    continue
                try:
                    block = os.read(descriptor, 65536)
                except BlockingIOError:
                    continue
                if not block:
                    raise RuntimeError('Kernel-Trace wurde geschlossen')
                pending += block
                lines = pending.split(b'\n')
                pending = lines.pop()
                for raw in lines:
                    line = raw.decode('utf-8', errors='replace').strip()
                    if 'LOST' in line and 'EVENTS' in line:
                        message = f'[Kernel-Debug] Trace-Ereignisse verloren: {line}'
                    elif selected(line):
                        message = f'[Kernel-PDP] {line}'
                    else:
                        continue
                    archive.write(message + '\n')
                    print(f'{color}{message}{reset}', flush=True)
    finally:
        os.close(descriptor)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('trace_pipe')
    parser.add_argument('ready_file')
    parser.add_argument('kernel_log')
    arguments = parser.parse_args()
    forward(arguments.trace_pipe, arguments.ready_file, arguments.kernel_log)


if __name__ == '__main__':
    main()

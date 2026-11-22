#!/usr/bin/env python3
"""Prüft zwei echte Öffnungs-/Entzugszyklen und den zugehörigen PEP-Nachweis."""
import json
from pathlib import Path
import re
import sys


def validate(events, runtime, pid):
    """Verlangt denselben Prozess/FD, erneute Versuche und zwei PEP-Schließungen."""
    held = False
    opens = revocations = denied_between = 0
    last_time = -1
    first_revoked = second_opened = None
    for event in events:
        if event['pid'] != pid or event['fd'] != 10:
            raise ValueError('PID oder FD im Zeitbeobachter unerwartet geändert')
        timestamp = event['unix_ns']
        if timestamp < last_time:
            raise ValueError('Ereignisse des Zeitbeobachters sind nicht chronologisch')
        last_time = timestamp
        kind = event['event']
        if kind == 'opened':
            if held:
                raise ValueError('Datei wurde erneut geöffnet, obwohl ihr FD noch offen war')
            held = True
            opens += 1
            if opens == 2:
                second_opened = timestamp
        elif kind == 'revoked':
            if not held:
                raise ValueError('Entzug ohne vorherige Dateiöffnung')
            held = False
            revocations += 1
            if revocations == 1:
                first_revoked = timestamp
            if revocations == 2:
                break
        elif kind == 'denied':
            if held:
                raise ValueError('Öffnungsversuch trotz gehaltenem FD')
            if revocations == 1 and opens == 1:
                denied_between += 1
        else:
            raise ValueError(f'Unbekanntes Ereignis: {kind}')
    if opens != 2 or revocations != 2 or denied_between == 0:
        raise ValueError('Zwei Öffnungen, zwei Entzüge und dazwischen verweigerte Versuche fehlen')
    # A second open after the next permit boundary must remain open until the
    # following deny boundary. Leave headroom for scheduling and scan latency.
    if last_time - second_opened < 8_000_000_000:
        raise ValueError('Die zweite Permit-Phase wurde nicht annähernd zehn Sekunden gehalten')
    if second_opened - first_revoked < 8_000_000_000:
        raise ValueError('Die zehnsekündige Deny-Phase wurde nicht nachgewiesen')
    time_closings = 0
    for scan in runtime.split('USERSPACE_PEP scan started ')[1:]:
        cause = re.match(r'cause=\[([^]]*)\]', scan)
        if cause and re.search(r'\btime:\d+', cause[1]):
            time_closings += len(re.findall(rf'USERSPACE_PEP closed pid={pid} fd=10\b', scan))
    if time_closings < 2:
        raise ValueError('Zwei zeitgetriggerte FD-Entzüge durch den Userspace-PEP fehlen im Runtime-Log')
    return denied_between


if __name__ == '__main__':
    directory, runtime_path, offset, pid = sys.argv[1:]
    events = [json.loads(line) for line in (Path(directory) / 'events.jsonl').read_text().splitlines()]
    runtime = '\n'.join(Path(runtime_path).read_text().splitlines()[int(offset):])
    try:
        denied = validate(events, runtime, int(pid))
    except ValueError as error:
        raise SystemExit(str(error))
    print(f'OK: derselbe Prozess, zwei FD-Entzüge; {denied} verweigerte Öffnungsversuche dazwischen.')

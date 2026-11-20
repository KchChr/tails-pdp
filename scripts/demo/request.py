#!/usr/bin/env python3
"""Render an Authorization Context with attributes read from the active maps by show-active."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import time


def describe(snapshot, command, uid, path, now=None):
    uid = os.getuid() if uid == '-' else int(uid)
    metadata = path.stat()
    device = (os.major(metadata.st_dev) << 20) | os.minor(metadata.st_dev)
    generation = re.search(r'generation policy=(\d+).*?attribute=(\d+)', snapshot)
    if generation is None:
        raise ValueError('show-active enthält keine lesbaren Generationsnummern.')

    attributes = {}
    in_attributes = False
    for line in snapshot.splitlines():
        if line == 'ATTRIBUTES:':
            in_attributes = True
            continue
        if not in_attributes:
            continue
        if line.startswith('system.'):
            selected = line
        elif line.startswith(f'subject:{uid} '):
            selected = line.split(' ', 1)[1]
        elif line.startswith(f'resource:{device}:{metadata.st_ino} '):
            selected = line.split(' ', 1)[1]
        else:
            continue
        name, separator, value = selected.partition(' = ')
        if separator:
            attributes[name] = value

    # Include missing attributes referenced by active policies: absence is
    # significant, e.g. subject.position in chapter 5. Never read source files.
    required = set(re.findall(r'attribute_condition=((?:system|subject|resource)\.[A-Za-z_][A-Za-z0-9_-]*)', snapshot))
    for name in required:
        attributes.setdefault(name, None)

    lines = [
        'action == "file_open";',
        f'command == {json.dumps(command, ensure_ascii=False)};',
        f'subject.uid == {uid};',
        f'resource.device == {device};',
        f'resource.inode == {metadata.st_ino};',
        f'resource.path == {json.dumps(str(path.absolute()), ensure_ascii=False)};',
        '',
        'Attribute:',
    ]
    lines.extend(
        f'{name} == {value};' if value is not None else f'# {name}: nicht vorhanden'
        for name, value in sorted(attributes.items())
    )
    if not attributes:
        lines.append('keine')
    if re.search(r'legacy_condition=(?:Time|Hour|Minute|Second)', snapshot):
        timestamp = int(time.time()) if now is None else int(now)
        utc = datetime.fromtimestamp(timestamp, timezone.utc)
        lines.extend([
            '',
            'Zeitkontext (Momentaufnahme der Systemzeit):',
            f'environment.time == {timestamp};',
            f'environment.utc.hour == {utc.hour};',
            f'environment.utc.minute == {utc.minute};',
            f'environment.utc.second == {utc.second};',
        ])
        for modulo in sorted(set(int(value) for value in re.findall(r'legacy_condition=Time % (\d+)', snapshot))):
            if modulo:
                lines.append(f'environment.time % {modulo} == {timestamp % modulo};')
    lines.extend([
        '',
        'Metadaten:',
        f'Aktiver Stand: Policygeneration {generation[1]}, Attributgeneration {generation[2]}',
    ])
    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('snapshot', type=Path)
    parser.add_argument('command')
    parser.add_argument('uid')
    parser.add_argument('file', type=Path)
    args = parser.parse_args()
    print(describe(args.snapshot.read_text(), args.command, args.uid, args.file))


if __name__ == '__main__':
    main()

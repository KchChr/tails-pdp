#!/usr/bin/env python3
"""Verify all local Cargo sources against their existing vendor checksums."""
import hashlib
import json
from pathlib import Path
import sys


def verify(root):
    manifests = sorted(root.glob('*/.cargo-checksum.json'))
    if not manifests:
        return 0, [f'Keine Vendor-Prüfsummen unter {root} gefunden.']
    errors = []
    count = 0
    for manifest in manifests:
        for relative, expected in json.loads(manifest.read_text())['files'].items():
            path = manifest.parent / relative
            count += 1
            if not path.is_file():
                errors.append(f'Fehlende Vendor-Datei: {path}')
            elif hashlib.sha256(path.read_bytes()).hexdigest() != expected:
                errors.append(f'Abweichende Vendor-Prüfsumme: {path}')
    return count, errors


def main():
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parents[1] / 'vendor'
    count, errors = verify(root)
    if errors:
        print('\n'.join(errors[:10]), file=sys.stderr)
        print(f'Offline-Quellen unvollständig oder verändert: {len(errors)} Fehler.', file=sys.stderr)
        return 1
    print(f'Offline-Quellen geprüft: {count} Dateien unverändert und vollständig.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

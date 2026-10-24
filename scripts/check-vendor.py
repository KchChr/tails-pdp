#!/usr/bin/env python3
"""Verify all local Cargo sources against their existing vendor checksums."""
import argparse
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


def verify_sysroot(root, manifest_path, installed_lock=None):
    """Check coverage as well as content: a whole missing crate has no own manifest."""
    metadata = json.loads(manifest_path.read_text())
    errors = []
    lock = manifest_path.parent / 'Cargo.lock'
    expected = metadata['cargo_lock_sha256']
    if hashlib.sha256(lock.read_bytes()).hexdigest() != expected:
        errors.append(f'Abweichendes Sysroot-Lockfile: {lock}')
    if installed_lock is not None:
        if not installed_lock.is_file() or hashlib.sha256(installed_lock.read_bytes()).hexdigest() != expected:
            errors.append(f'rust-src passt nicht zum mitgelieferten Sysroot-Lockfile: {installed_lock}')
    pin = manifest_path.parent.parent / 'ebpf-toolchain'
    if pin.read_text().strip() != metadata['toolchain']:
        errors.append('eBPF-Toolchain und Sysroot-Manifest stimmen nicht überein.')
    for package in metadata['packages']:
        checksum = root / f"{package['name']}-{package['version']}" / '.cargo-checksum.json'
        if not checksum.is_file():
            errors.append(f'Fehlende Sysroot-Abhängigkeit: {checksum.parent}')
        elif json.loads(checksum.read_text())['package'] != package['checksum']:
            errors.append(f'Abweichende Sysroot-Paketprüfsumme: {checksum.parent}')
    return errors


def main():
    project = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', nargs='?', type=Path, default=project / 'vendor')
    parser.add_argument('--sysroot-lock', type=Path, help='Cargo.lock der installierten rust-src-Komponente')
    args = parser.parse_args()
    root = args.root
    count, errors = verify(root)
    errors.extend(verify_sysroot(root, project / 'nix-config/ebpf-sysroot/registry.json', args.sysroot_lock))
    if errors:
        print('\n'.join(errors[:10]), file=sys.stderr)
        print(f'Offline-Quellen unvollständig oder verändert: {len(errors)} Fehler.', file=sys.stderr)
        return 1
    print(f'Offline-Quellen geprüft: {count} Dateien unverändert und vollständig.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

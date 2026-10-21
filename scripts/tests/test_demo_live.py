#!/usr/bin/env python3
"""Run the real tmux demo under a PTY; archive evidence even on failure."""
import fcntl
import errno
import hashlib
import json
import os
from pathlib import Path
import pty
import select
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import termios
import time
import traceback

PROJECT = Path(__file__).resolve().parents[2]
HOST_PINS = Path('/sys/fs/bpf/tails-pdp')


def run_in_pty(command, environment, logfile, timeout, grace=15):
    """Return exit status and timeout flag, draining output through child exit."""
    pid, terminal = pty.fork()
    if pid == 0:
        try:
            fcntl.ioctl(0, termios.TIOCSWINSZ, struct.pack('HHHH', 45, 160, 0, 0))
            os.execvpe(command[0], command, environment)
        except Exception:
            traceback.print_exc()
            os._exit(127)
    deadline = time.monotonic() + timeout
    timed_out = False
    killed = False
    status = None
    eof = False
    try:
        with logfile.open('wb') as output:
            while status is None or not eof:
                if not eof and select.select([terminal], [], [], 0.1)[0]:
                    try:
                        block = os.read(terminal, 65536)
                    except OSError as error:
                        # Linux and macOS PTYs report EIO once the slave closes.
                        if error.errno != errno.EIO:
                            raise
                        block = b''
                    if block:
                        output.write(block)
                    else:
                        eof = True
                if eof and status is None:
                    time.sleep(0.01)
                if status is None:
                    reaped, value = os.waitpid(pid, os.WNOHANG)
                    if reaped:
                        status = os.waitstatus_to_exitcode(value)
                if time.monotonic() >= deadline:
                    if not timed_out:
                        timed_out = True
                        try:
                            os.killpg(pid, signal.SIGTERM)
                        except ProcessLookupError:
                            pass
                        deadline = time.monotonic() + grace
                    elif not killed:
                        killed = True
                        try:
                            os.killpg(pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        deadline = time.monotonic() + 2
                    else:
                        break  # Never hang on a descendant holding the PTY open.
            return status, timed_out
    finally:
        os.close(terminal)
        if status is None:
            try:
                os.killpg(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            os.waitpid(pid, 0)


def pin_snapshot():
    if not HOST_PINS.exists():
        return {}
    return {str(path.relative_to(HOST_PINS)): (path.stat().st_dev, path.stat().st_ino, path.stat().st_mode)
            for path in HOST_PINS.rglob('*')}


def workspace_snapshot(project=PROJECT):
    snapshot = {}
    for name in ('policies', 'attributes', 'demo/files'):
        root = project / name
        if not root.exists():
            continue
        for path in [root, *root.rglob('*')]:
            metadata = path.lstat()
            value = (metadata.st_dev, metadata.st_ino, metadata.st_mode)
            if path.is_symlink():
                value += (os.readlink(path),)
            elif path.is_file():
                value += (hashlib.sha256(path.read_bytes()).hexdigest(),)
            snapshot[str(path.relative_to(project))] = value
    return snapshot


def validate_demo(fixture, launcher_status, timed_out):
    if timed_out:
        raise AssertionError('Gesamtzeitlimit der Demo überschritten')
    if launcher_status != 0:
        raise AssertionError(f'Demo-Launcher fehlgeschlagen: {launcher_status}')
    if (fixture / 'exit-status').read_text().strip() != '0':
        raise AssertionError('Demo-Worker hat keinen Erfolg gemeldet')
    transcript = (fixture / 'transcript.log').read_text(errors='replace')
    if 'Alle Demo-Kapitel erfolgreich geprüft.' not in transcript:
        raise AssertionError('Vollständiger Demo-Abschluss fehlt')
    if 'Eigener bpffs-Mount:' not in transcript:
        raise AssertionError('Privates Demo-bpffs nicht bestätigt')
    if 'Kernel debug logging mode=Deny' not in (fixture / 'runtime.log').read_text(errors='replace'):
        raise AssertionError('Reduzierter Kernel-Loggingmodus fehlt; aktuelle Binaries neu bauen')
    kernel_log = (fixture / 'kernel.log').read_text(errors='replace')
    if 'Trace-Ereignisse verloren:' in kernel_log:
        raise AssertionError('Kernel-Trace-Ereignisse gingen während der Demo verloren')
    if not any(line.startswith('[Kernelspace-PEP]') and 'file_open final=deny' in line for line in kernel_log.splitlines()):
        raise AssertionError('Keine Deny-Entscheidung des Kernelspace-PEP im Debuglog nachgewiesen')


def main():
    if sys.platform != 'linux' or os.geteuid() != 0:
        print('Der Live-Demotest benötigt root auf dem dedizierten Linux-Zielsystem.', file=sys.stderr)
        return 1
    results = os.environ.get('TAILS_PDP_TEST_RESULTS_DIR')
    (PROJECT / 'test-results').mkdir(exist_ok=True)
    archive = Path(results) / 'demo' if results else Path(tempfile.mkdtemp(prefix='demo-', dir=PROJECT / 'test-results'))
    archive.mkdir(parents=True, exist_ok=True)
    path_file = archive / 'fixture-path.txt'
    # Never let an old marker turn an early launcher failure into a valid run.
    path_file.unlink(missing_ok=True)
    environment = {**os.environ, 'TERM': 'xterm-256color', 'DEMO_ARTIFACT_PATH_FILE': str(path_file),
                   'PYTHONDONTWRITEBYTECODE': '1'}
    report = {'command': ['./scripts/demo.sh', '--auto'], 'success': False}
    fixture = None
    sentinel = None
    created_pin_directory = False
    started = time.monotonic()
    try:
        timeout = float(os.environ.get('DEMO_TEST_TIMEOUT_SECONDS', '300'))
        if not 0 < timeout < float('inf'):
            raise ValueError('DEMO_TEST_TIMEOUT_SECONDS muss positiv und endlich sein')
        # A directory in host bpffs exercises the former "existing pins" failure
        # without creating or altering someone else's maps.
        filesystem = subprocess.run(['stat', '-f', '-c', '%T', '/sys/fs/bpf'], capture_output=True, text=True, check=True)
        if filesystem.stdout.strip() == 'bpf_fs':
            created_pin_directory = not HOST_PINS.exists()
            HOST_PINS.mkdir(exist_ok=True)
            sentinel = Path(tempfile.mkdtemp(prefix='demo-test-', dir=HOST_PINS))
        report['host_pin_sentinel'] = str(sentinel) if sentinel else None
        before = pin_snapshot()
        original_workspace = workspace_snapshot()
        status, timed_out = run_in_pty([str(PROJECT / 'scripts/demo.sh'), '--auto'], environment,
                                     archive / 'terminal.log', timeout)
        report.update(launcher_status=status, timed_out=timed_out)
        if workspace_snapshot() != original_workspace:
            raise AssertionError('Originalverzeichnisse wurden nach der Demo nicht unverändert wiederhergestellt')
        report['original_workspace_restored'] = True
        if pin_snapshot() != before:
            raise AssertionError('Host-Pins wurden während der Demo verändert')
        report['host_pins_unchanged'] = True
        if not path_file.exists():
            raise AssertionError('Demo hat kein Artefaktverzeichnis gemeldet; siehe terminal.log')
        fixture = Path(path_file.read_text().strip())
        validate_demo(fixture, status, timed_out)
        report['success'] = True
    except Exception:
        report['error'] = traceback.format_exc()
        print(report['error'], file=sys.stderr)
    finally:
        if fixture is None and path_file.exists():
            fixture = Path(path_file.read_text().strip())
        operations = []
        if fixture is not None and fixture.is_dir():
            operations.append(lambda: shutil.copytree(fixture, archive / 'fixture', dirs_exist_ok=True))
        if sentinel is not None:
            operations.append(sentinel.rmdir)
        if created_pin_directory:
            operations.append(HOST_PINS.rmdir)
        for operation in operations:
            try:
                operation()
            except Exception:
                report['success'] = False
                report.setdefault('archive_or_cleanup_errors', []).append(traceback.format_exc())
        report['elapsed_seconds'] = time.monotonic() - started
        (archive / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
        if os.environ.get('SUDO_UID') and os.environ.get('SUDO_GID'):
            uid, gid = int(os.environ['SUDO_UID']), int(os.environ['SUDO_GID'])
            for path in [*archive.rglob('*'), archive]:
                os.chown(path, uid, gid, follow_symlinks=False)
        print(f'Demo-Testartefakte: {archive}')
    return 0 if report['success'] else 1


if __name__ == '__main__':
    raise SystemExit(main())

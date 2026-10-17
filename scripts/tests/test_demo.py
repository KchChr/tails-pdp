#!/usr/bin/env python3
"""Unprivileged demo checks: launcher bootstrap and real helper error paths."""
import contextlib
import errno
import io
import json
import os
from pathlib import Path
import pty
import runpy
import shlex
import shutil
import subprocess
import tempfile
import types
import unittest
from unittest.mock import patch

PROJECT = Path(__file__).resolve().parents[2]
probe = types.ModuleType("demo_probe")
exec(compile((PROJECT / "scripts/demo/probe.py").read_text(), "probe.py", "exec"), probe.__dict__)
live = types.SimpleNamespace(**runpy.run_path(str(PROJECT / 'scripts/tests/test_demo_live.py')))


class ProbeTests(unittest.TestCase):
    def test_access_distinguishes_eperm_from_dac_or_io_errors(self):
        for error, expected in [(errno.EPERM, "deny\n"), (errno.EACCES, None), (errno.ENOENT, None)]:
            with self.subTest(error=error), patch.object(probe, "set_command"), patch.object(probe.os, "open", side_effect=OSError(error, "test")):
                if expected:
                    output = io.StringIO()
                    with contextlib.redirect_stdout(output):
                        probe.access("target", "demo", "-")
                    self.assertEqual(output.getvalue(), expected)
                else:
                    with self.assertRaises(OSError):
                        probe.access("target", "demo", "-")

    def test_access_closes_open_fd_and_sets_only_real_uid(self):
        with tempfile.NamedTemporaryFile() as target, patch.object(probe, "set_command"), patch.object(probe.os, "setresuid", create=True) as uid:
            before = os.open(target.name, os.O_RDONLY)
            os.close(before)
            with contextlib.redirect_stdout(io.StringIO()) as output:
                probe.access(target.name, "cat", "60001")
            uid.assert_called_once_with(60001, 0, 0)
            self.assertEqual(output.getvalue(), "allow\n")
            self.assertFalse(probe.is_open(before))

    def test_fd_closed_requires_ebadf(self):
        with patch.object(probe.os, "fstat", side_effect=OSError(errno.EIO, "test")):
            with self.assertRaises(OSError):
                probe.is_open(123)

    @unittest.skipUnless(os.uname().sysname == "Linux", "PR_SET_NAME requires Linux")
    def test_real_holder_survives_selective_fd_closure(self):
        # Run inside a child so the test can close the helper's own FDs without ptrace.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "target").write_text("target")
            (root / "safe").write_text("safe")
            program = '''
import json, os, runpy, sys
from pathlib import Path
p = runpy.run_path(sys.argv[1])
root = Path(sys.argv[2])
ticks = 0
def tick(_):
    global ticks
    ticks += 1
    if ticks == 1:
        ready = json.loads((root / 'ready.json').read_text())
        for fd in ready['protected']: os.close(fd)
    else:
        state = json.loads((root / 'state.json').read_text())
        assert state['protected'] == [False] * 3, state
        assert state['controls'] == [True] * 2, state
        raise SystemExit(0)
p['time'].sleep = tick
p['hold'](str(root / 'target'), str(root / 'safe'), str(root))
'''
            subprocess.run([shutil.which("python3"), "-c", program, str(PROJECT / "scripts/demo/probe.py"), directory], check=True, capture_output=True, timeout=5)


class LauncherTests(unittest.TestCase):
    def run_launcher(self, with_tmux):
        with tempfile.TemporaryDirectory(prefix="demo test ") as directory:
            root = Path(directory)
            binaries = root / "bin"
            binaries.mkdir()
            commands = "bash cat chmod chown date dirname env flock grep id ln mkdir mktemp mount mv pgrep ps python3 readlink rm sleep stat sudo tail tee uname unshare wc".split()
            for command in commands:
                executable = shutil.which(command)
                if executable:
                    (binaries / command).symlink_to(executable)
                else:
                    (binaries / command).write_text("#!/bin/sh\nexit 0\n")
                    (binaries / command).chmod(0o755)
            # Override without following symlinks into system binaries.
            for name, content in {
                "uname": '#!/bin/sh\necho Linux\n',
                "sudo": '#!/bin/sh\nexit 0\n',
                "nix-shell": '''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
Path(os.environ['CALLS']).write_text(json.dumps(sys.argv[1:]))
''',
            }.items():
                path = binaries / name
                path.unlink(missing_ok=True)
                path.write_text(content)
                path.chmod(0o755)
            # A Nix-shell sudo may shadow the host wrapper; the launcher must
            # authenticate and launch the worker through the selected host path.
            system_sudo = binaries / "system-sudo"
            system_sudo.write_text('#!/bin/sh\nexit 0\n')
            system_sudo.chmod(0o755)
            (binaries / "sudo").write_text('#!/bin/sh\necho "wrong sudo" >&2\nexit 99\n')
            if with_tmux:
                (binaries / "tmux").write_text('''#!/usr/bin/env python3
import json, os, shlex, sys
from pathlib import Path
args = sys.argv[1:]
with open(os.environ['CALLS'], 'a') as log: log.write(json.dumps(args) + '\\n')
if 'respawn-pane' in args:
    command = shlex.split(args[-1])
    if os.geteuid() != 0:
        assert command[0] == os.environ['DEMO_SUDO_BIN'], command
    root = Path(command[command.index('--worker') + 1].rstrip(';'))
    Path(os.environ['DEMO_ROOT_CAPTURE']).write_text(str(root))
    (root / 'exit-status').write_text('0\\n')
''')
                (binaries / "tmux").chmod(0o755)
            environment = {**os.environ, "PATH": str(binaries), "CALLS": str(root / "calls"), "DEMO_ROOT_CAPTURE": str(root / "demo-root"),
                           "TAILS_PDP_BIN": "/usr/bin/true", "ADM_TOOL_BIN": "/usr/bin/true", "DEMO_SUDO_BIN": str(system_sudo),
                           "DEMO_ARTIFACT_PATH_FILE": str(root / "artifact-path")}
            environment.pop("TAILS_DEMO_NIX", None)
            primary, secondary = pty.openpty()
            try:
                result = subprocess.run([str(PROJECT / "scripts/demo.sh"), "--auto"], env=environment,
                                        stdin=secondary, stdout=secondary, stderr=secondary, timeout=8)
                self.assertEqual(result.returncode, 0)
                if with_tmux:
                    self.assertEqual((root / 'artifact-path').read_text().strip(), (root / 'demo-root').read_text())
            finally:
                os.close(secondary)
                os.close(primary)
                if (root / "demo-root").exists():
                    shutil.rmtree((root / "demo-root").read_text())
            return (root / "calls").read_text()

    def test_missing_programs_reexec_via_nix(self):
        arguments = json.loads(self.run_launcher(False))
        self.assertEqual(arguments[0], str(PROJECT / "scripts/demo/shell.nix"))
        self.assertEqual(arguments[1], "--run")
        self.assertEqual(shlex.split(arguments[2]), ["bash", str(PROJECT / "scripts/demo.sh"), "--auto"])

    def test_tmux_layout_and_worker_are_configured_before_attach(self):
        calls = [json.loads(line) for line in self.run_launcher(True).splitlines()]
        self.assertEqual(sum('split-window' in call for call in calls), 2)
        self.assertEqual(sum('respawn-pane' in call for call in calls), 1)
        worker_index = next(i for i, call in enumerate(calls) if 'respawn-pane' in call)
        attach_index = next(i for i, call in enumerate(calls) if 'attach-session' in call)
        self.assertLess(worker_index, attach_index)
        self.assertIn('kill-server', calls[-1])


class LiveRunnerTests(unittest.TestCase):
    def test_pty_provides_terminal_and_propagates_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / 'terminal.log'
            command = [shutil.which('python3'), '-c',
                       'import os,sys; print("tty", os.isatty(0), os.isatty(1), flush=True); sys.exit(7)']
            status, timed_out = live.run_in_pty(command, os.environ, log, timeout=5)
            self.assertEqual(status, 7)
            self.assertFalse(timed_out)
            self.assertIn('tty True True', log.read_text())

    def test_pty_timeout_stops_process_and_keeps_output(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / 'terminal.log'
            command = [shutil.which('python3'), '-c', 'import time; print("started", flush=True); time.sleep(60)']
            _, timed_out = live.run_in_pty(command, os.environ, log, timeout=0.5, grace=1)
            self.assertTrue(timed_out)
            self.assertIn('started', log.read_text())

    def test_success_requires_completed_demo_not_just_exit_zero(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory)
            (fixture / 'exit-status').write_text('0\n')
            (fixture / 'transcript.log').write_text('Eigener bpffs-Mount:\n')
            with self.assertRaisesRegex(AssertionError, 'Demo-Abschluss fehlt'):
                live.validate_demo(fixture, 0, False)
            with (fixture / 'transcript.log').open('a') as output:
                output.write('Alle Demo-Kapitel erfolgreich geprüft.\n')
            live.validate_demo(fixture, 0, False)
            with self.assertRaisesRegex(AssertionError, 'Gesamtzeitlimit'):
                live.validate_demo(fixture, 0, True)
            with self.assertRaisesRegex(AssertionError, 'Launcher fehlgeschlagen'):
                live.validate_demo(fixture, 1, False)


class MountNamespaceTests(unittest.TestCase):
    def check_namespace(self, parent_namespace, mount_failure=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'host-pin').write_text('preserve')
            script = '''
source "$1"
readlink() { printf 'mnt:[demo]\\n'; }
mount() { printf '%s\\n' "$@" > "$TEST_MOUNT/log"; return "$MOUNT_STATUS"; }
stat() { printf 'bpf_fs\\n'; }
setup_demo_bpffs "$TEST_MOUNT"
'''
            environment = {**os.environ, 'TEST_MOUNT': directory, 'MOUNT_STATUS': '1' if mount_failure else '0'}
            environment.pop('DEMO_PARENT_MOUNT_NS', None)
            if parent_namespace is not None:
                environment['DEMO_PARENT_MOUNT_NS'] = parent_namespace
            result = subprocess.run([shutil.which('bash'), '-c', script, 'test', str(PROJECT / 'scripts/demo/runner.sh')],
                                    env=environment, capture_output=True, text=True, timeout=5)
            self.assertEqual((root / 'host-pin').read_text(), 'preserve')
            calls = (root / 'log').read_text().splitlines() if (root / 'log').exists() else []
            return result, calls

    def test_no_mount_without_namespace_change(self):
        for parent in (None, 'mnt:[demo]'):
            with self.subTest(parent=parent):
                result, calls = self.check_namespace(parent)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(calls, [])
                self.assertIn('Privater Mount-Namespace fehlt', result.stderr)

    def test_private_namespace_gets_fresh_bpffs(self):
        result, calls = self.check_namespace('mnt:[host]')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls[:5], ['-t', 'bpf', '-o', 'mode=700', 'bpf'])

    def test_mount_failure_does_not_continue(self):
        result, _ = self.check_namespace('mnt:[host]', mount_failure=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Demo-bpffs konnte nicht eingehängt', result.stderr)


class SudoResolutionTests(unittest.TestCase):
    def resolve(self, script, environment):
        return subprocess.run(
            [shutil.which("bash"), "-c", 'source "$1"; ' + script, "test", str(PROJECT / "scripts/demo/dependencies.sh")],
            env=environment, text=True, capture_output=True, timeout=5,
        )

    def test_explicit_system_wrapper_wins_over_broken_path_sudo(self):
        with tempfile.TemporaryDirectory(prefix="sudo wrapper ") as directory:
            root = Path(directory)
            system_sudo = root / "system-sudo"
            system_sudo.write_text('#!/bin/sh\nexit 0\n')
            system_sudo.chmod(0o755)
            (root / "sudo").write_text('#!/bin/sh\nexit 99\n')
            (root / "sudo").chmod(0o755)
            result = self.resolve('resolve_demo_sudo', {**os.environ, "PATH": directory, "DEMO_SUDO_BIN": str(system_sudo)})
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), str(system_sudo))

    def test_nixos_wrapper_is_preferred_to_path(self):
        # Model the executable wrapper without writing to the host's /run.
        with tempfile.TemporaryDirectory() as directory:
            wrapper = Path(directory) / 'sudo'
            wrapper.write_text('#!/bin/sh\nexit 0\n')
            wrapper.chmod(0o755)
            environment = {**os.environ, "TEST_NIXOS_WRAPPER": str(wrapper)}
            environment.pop('DEMO_SUDO_BIN', None)
            result = self.resolve('resolve_demo_sudo "$TEST_NIXOS_WRAPPER"', environment)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), str(wrapper))

    def test_store_sudo_is_rejected(self):
        result = self.resolve('resolve_demo_sudo', {**os.environ, "DEMO_SUDO_BIN": "/nix/store/example-sudo/bin/sudo"})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Systemwrapper', result.stderr)


if __name__ == "__main__":
    unittest.main()

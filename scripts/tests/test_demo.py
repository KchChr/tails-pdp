#!/usr/bin/env python3
"""Unprivileged demo checks: launcher bootstrap and real helper error paths."""
import contextlib
import errno
import io
import json
import os
from pathlib import Path
import runpy
import shlex
import shutil
import subprocess
import tempfile
import time
import types
import unittest
from unittest.mock import patch

PROJECT = Path(__file__).resolve().parents[2]
probe = types.ModuleType("demo_probe")
exec(compile((PROJECT / "scripts/demo/probe.py").read_text(), "probe.py", "exec"), probe.__dict__)
live = types.SimpleNamespace(**runpy.run_path(str(PROJECT / 'scripts/tests/test_demo_live.py')))
kernel_trace = types.SimpleNamespace(**runpy.run_path(str(PROJECT / 'scripts/demo/kernel_trace.py')))


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
            commands = "bash cat chmod chown date dirname env flock grep id ln mkdir mktemp mount mv pgrep ps python3 readlink rm rmdir sleep stat sudo tail tee uname unshare wc".split()
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
            # NixOS does not provide FHS paths such as /usr/bin/true. This
            # fixture also exercises quoting of binary paths containing spaces.
            demo_binary = root / 'demo binary'
            demo_binary.write_text('#!/bin/sh\nexit 0\n')
            demo_binary.chmod(0o755)
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
                           "TAILS_PDP_BIN": str(demo_binary), "ADM_TOOL_BIN": str(demo_binary), "DEMO_SUDO_BIN": str(system_sudo),
                           "DEMO_ARTIFACT_PATH_FILE": str(root / "artifact-path")}
            environment.pop("TAILS_DEMO_NIX", None)
            try:
                terminal_log = root / 'terminal.log'
                status, timed_out = live.run_in_pty([str(PROJECT / 'scripts/demo.sh'), '--auto'],
                                                  environment, terminal_log, timeout=20, grace=2)
                diagnostic = terminal_log.read_text(errors='replace')
                self.assertFalse(timed_out, f'Launcher-Test überschritt das Zeitlimit:\n{diagnostic}')
                self.assertEqual(status, 0, f'Launcher-Ausgabe:\n{diagnostic}')
                if with_tmux:
                    self.assertEqual((root / 'artifact-path').read_text().strip(), (root / 'demo-root').read_text())
            finally:
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
        self.assertTrue(any('status-format[1]' in call and 'Legende:' in call[-1] for call in calls))


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
            (fixture / 'kernel.log').write_text('[Kernel-PDP] cat-42: file_open final=deny\n')
            (fixture / 'runtime.log').write_text('Kernel debug logging mode=Deny\n')
            with self.assertRaisesRegex(AssertionError, 'Demo-Abschluss fehlt'):
                live.validate_demo(fixture, 0, False)
            with (fixture / 'transcript.log').open('a') as output:
                output.write('Alle Demo-Kapitel erfolgreich geprüft.\n')
            live.validate_demo(fixture, 0, False)
            with self.assertRaisesRegex(AssertionError, 'Gesamtzeitlimit'):
                live.validate_demo(fixture, 0, True)
            with self.assertRaisesRegex(AssertionError, 'Launcher fehlgeschlagen'):
                live.validate_demo(fixture, 1, False)
            (fixture / 'kernel.log').write_text('')
            with self.assertRaisesRegex(AssertionError, 'Kernel-Deny-Entscheidung'):
                live.validate_demo(fixture, 0, False)
            (fixture / 'kernel.log').write_text('[Kernel-Debug] Trace-Ereignisse verloren: CPU:2 [LOST 2 EVENTS]\n')
            with self.assertRaisesRegex(AssertionError, 'Trace-Ereignisse gingen'):
                live.validate_demo(fixture, 0, False)
            (fixture / 'runtime.log').write_text('Kernel debug logging mode=Verbose\n')
            with self.assertRaisesRegex(AssertionError, 'Reduzierter Kernel-Loggingmodus fehlt'):
                live.validate_demo(fixture, 0, False)


class KernelTraceTests(unittest.TestCase):
    def test_filter_only_keeps_final_denials_and_tail_call_failures(self):
        prefix = 'cat-42 [001] d..2 123.456: bpf_trace_printk: '
        self.assertTrue(kernel_trace.selected(prefix + 'file_open final=deny'))
        self.assertTrue(kernel_trace.selected(prefix + 'file_open tail_call=failed stage=stream'))
        for message in ('file_open final=permit', 'file_open uid=60001', 'fos deny=1 permit=0', 'unrelated message'):
            with self.subTest(message=message):
                self.assertFalse(kernel_trace.selected(prefix + message))

    def test_reader_discards_old_records_and_forwards_live_denial(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pipe = root / 'trace_pipe'
            os.mkfifo(pipe)
            feed = os.open(pipe, os.O_RDWR | os.O_NONBLOCK)
            process = None
            try:
                os.write(feed, b'old: file_open final=deny\n')
                process = subprocess.Popen([shutil.which('python3'), str(PROJECT / 'scripts/demo/kernel_trace.py'),
                                            str(pipe), str(root / 'ready'), str(root / 'kernel.log')],
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                deadline = time.monotonic() + 5
                while not (root / 'ready').exists():
                    self.assertIsNone(process.poll(), 'Trace reader exited before readiness')
                    self.assertLess(time.monotonic(), deadline, 'Trace reader readiness timeout')
                    time.sleep(0.01)
                os.write(feed, b'new: file_open final=permit\nnew: file_open final=deny\n')
                while not (root / 'kernel.log').exists() or 'new:' not in (root / 'kernel.log').read_text():
                    self.assertLess(time.monotonic(), deadline, 'Trace reader output timeout')
                    time.sleep(0.01)
                process.terminate()
                output, error = process.communicate(timeout=3)
                self.assertEqual(process.returncode, 0, error)
                self.assertIn('[Kernel-PDP] new: file_open final=deny', output)
                self.assertNotIn('old:', output)
                self.assertNotIn('final=permit', output)
            finally:
                os.close(feed)
                if process is not None and process.poll() is None:
                    process.kill()
                    process.communicate(timeout=3)


class WorkspaceTests(unittest.TestCase):
    def run_workspace(self, root, script):
        run = root / 'demo/runs/test'
        run.mkdir(parents=True, exist_ok=True)
        environment = {**os.environ, 'PROJECT_ROOT': str(root), 'TEST_RUN': str(run)}
        setup = '''
set -Eeuo pipefail
source "$1"
demo_root="$TEST_RUN"
owns_workspace=0
workspace_dirs=()
'''
        return subprocess.run([shutil.which('bash'), '-c', setup + script, 'test', str(PROJECT / 'scripts/demo/runner.sh')],
                              env=environment, text=True, capture_output=True, timeout=5)

    def test_original_directories_are_restored_and_demo_files_archived(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for path in ('policies', 'attributes', 'demo/files'):
                (root / path).mkdir(parents=True)
                (root / path / 'original').write_text(path)
            before = live.workspace_snapshot(root)
            result = self.run_workspace(root, '''
prepare_demo_workspace
printf demo > "$PROJECT_ROOT/policies/demo.policy"
printf changed > "$PROJECT_ROOT/attributes/system.attributes"
printf protected > "$PROJECT_ROOT/demo/files/protected.txt"
restore_demo_workspace
''')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(live.workspace_snapshot(root), before)
            for path in ('policies', 'attributes', 'demo/files'):
                self.assertEqual((root / path / 'original').read_text(), path)
                self.assertEqual(len(list((root / path).iterdir())), 1)
            self.assertEqual((root / 'demo/runs/test/policies/demo.policy').read_text(), 'demo')
            self.assertEqual((root / 'demo/runs/test/files/protected.txt').read_text(), 'protected')
            self.assertFalse((root / 'demo/.workspace-active').exists())

    def test_absent_original_directories_remain_absent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = self.run_workspace(root, 'prepare_demo_workspace\nrestore_demo_workspace\n')
            self.assertEqual(result.returncode, 0, result.stderr)
            for path in ('policies', 'attributes', 'demo/files'):
                self.assertFalse((root / path).exists())

    def test_unfinished_workspace_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'demo/.workspace-active').mkdir(parents=True)
            (root / 'policies').mkdir()
            (root / 'policies/existing').write_text('preserve')
            result = self.run_workspace(root, 'prepare_demo_workspace\n')
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual((root / 'policies/existing').read_text(), 'preserve')

    def test_interrupted_legacy_run_is_recovered_without_losing_demo_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            backup = root / 'demo/runs/run.old/original'
            marker = root / 'demo/.workspace-active'
            marker.mkdir(parents=True)
            (marker / 'backup-path').write_text(str(backup) + '\n')
            for name in ('policies', 'attributes'):
                (backup / name).mkdir(parents=True)
                (backup / name / 'original').write_text(name)
                (root / name).mkdir()
                (root / name / 'demo-data').write_text('keep')
            result = self.run_workspace(root, 'prepare_demo_workspace\nrestore_demo_workspace\n')
            self.assertEqual(result.returncode, 0, result.stderr)
            for name in ('policies', 'attributes'):
                self.assertEqual((root / name / 'original').read_text(), name)
            recovery = next((root / 'demo/runs/test').glob('recovered.*'))
            self.assertEqual((recovery / 'policies/demo-data').read_text(), 'keep')
            self.assertEqual((recovery / 'attributes/demo-data').read_text(), 'keep')
            self.assertTrue((recovery / 'previous-marker/backup-path').exists())
            self.assertFalse(marker.exists())

    def test_recovery_preserves_already_restored_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            backup = root / 'demo/runs/run.old/original'
            (backup / 'attributes').mkdir(parents=True)
            (backup / 'attributes/original').write_text('attributes')
            (root / 'policies').mkdir()
            (root / 'policies/original').write_text('already restored')
            marker = root / 'demo/.workspace-active'
            marker.mkdir()
            (marker / 'backup-path').write_text(str(backup))
            result = self.run_workspace(root, 'prepare_demo_workspace\nrestore_demo_workspace\n')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((root / 'policies/original').read_text(), 'already restored')
            self.assertEqual((root / 'attributes/original').read_text(), 'attributes')

    def test_recovery_manifest_restores_originally_absent_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            backup = root / 'demo/runs/run.old/original'
            backup.mkdir(parents=True)
            (backup / 'directories.present').write_text('')
            (root / 'demo/files').mkdir()
            (root / 'demo/files/protected.txt').write_text('demo data')
            marker = root / 'demo/.workspace-active'
            marker.mkdir()
            (marker / 'backup-path').write_text(str(backup))
            result = self.run_workspace(root, 'prepare_demo_workspace\nrestore_demo_workspace\n')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse((root / 'demo/files').exists())
            recovery = next((root / 'demo/runs/test').glob('recovered.*'))
            self.assertEqual((recovery / 'files/protected.txt').read_text(), 'demo data')

    def test_recovery_rejects_backup_outside_demo_runs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            backup = root / 'unrelated/original'
            (backup / 'policies').mkdir(parents=True)
            (backup / 'policies/original').write_text('preserve')
            marker = root / 'demo/.workspace-active'
            marker.mkdir(parents=True)
            (marker / 'backup-path').write_text(str(backup))
            result = self.run_workspace(root, 'prepare_demo_workspace\n')
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual((backup / 'policies/original').read_text(), 'preserve')
            self.assertTrue(marker.exists())

    def test_restore_failure_retains_backup_and_recovery_marker(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'policies').mkdir()
            (root / 'policies/original').write_text('preserve')
            result = self.run_workspace(root, '''
prepare_demo_workspace
mv() {
    if [[ "$2" == "$PROJECT_ROOT/policies" ]]; then return 1; fi
    command mv "$@"
}
restore_demo_workspace
''')
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual((root / 'demo/runs/test/original/policies/original').read_text(), 'preserve')
            self.assertTrue((root / 'demo/.workspace-active/backup-path').exists())


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

#!/usr/bin/env python3
"""Unprivileged demo checks: launcher bootstrap and real helper error paths."""
import contextlib
import errno
import hashlib
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
vendor_check = types.SimpleNamespace(**runpy.run_path(str(PROJECT / 'scripts/check-vendor.py')))
time_observer_check = types.SimpleNamespace(**runpy.run_path(str(PROJECT / 'scripts/demo/time-observer-check.py')))
request_view = types.SimpleNamespace(**runpy.run_path(str(PROJECT / 'scripts/demo/request.py')))


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


class BashObserverTests(unittest.TestCase):
    @unittest.skipUnless(Path('/proc/self/fd').is_dir(), 'Der Bash-FD-Beobachter benötigt Linux /proc')
    def test_bash_holds_real_descriptors_and_reports_proc_listing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target, control = root / 'protected.txt', root / 'control.txt'
            target.write_text('protected')
            control.write_text('control')
            with (root / 'output.log').open('w') as output:
                process = subprocess.Popen(
                    [shutil.which('bash'), str(PROJECT / 'scripts/demo/fd-observer.sh'),
                     str(target), str(control), directory],
                    stdout=output, stderr=subprocess.STDOUT,
                )
                try:
                    deadline = time.monotonic() + 5
                    while not (root / 'state.json').exists() and time.monotonic() < deadline:
                        self.assertIsNone(process.poll(), (root / 'output.log').read_text())
                        time.sleep(0.05)
                    state = json.loads((root / 'state.json').read_text())
                    ready = json.loads((root / 'ready.json').read_text())
                    self.assertEqual(ready['pid'], process.pid)
                    self.assertEqual(state['protected'], [True] * 3)
                    self.assertEqual(state['controls'], [True] * 2)
                    for key, path in [('protected', target), ('controls', control)]:
                        for fd in ready[key]:
                            self.assertTrue(os.path.samefile(f'/proc/{process.pid}/fd/{fd}', path))
                    transcript = (root / 'output.log').read_text()
                    self.assertIn('$ exec 10<', transcript)
                    self.assertIn(f'$ ls -l /proc/{process.pid}/fd', transcript)
                    self.assertIn('10: offen', transcript)
                    self.assertEqual(Path(f'/proc/{process.pid}/comm').read_text().strip(), 'bash')
                finally:
                    process.terminate()
                    try:
                        process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()


class TimeObserverTests(unittest.TestCase):
    def fixture(self):
        events = []
        for kind, second in [('opened', 100), ('revoked', 110),
                             *[('denied', second) for second in range(110, 120)],
                             ('opened', 120), ('revoked', 130)]:
            events.append(dict(event=kind, unix_ns=second * 1_000_000_000, pid=4242, fd=10))
        runtime = ''.join(
            f'USERSPACE_PEP scan started cause=[time:{second}] policy_generation=1 attribute_generation=1\n'
            'USERSPACE_PEP closed pid=4242 fd=10 for File policy Stream[0]\n'
            'USERSPACE_PEP scan completed policy_generation=1 attribute_generation=1\n'
            for second in [110, 130]
        )
        return events, runtime

    def test_two_cycles_include_ten_denials_and_real_time_triggered_pep_closings(self):
        events, runtime = self.fixture()
        self.assertEqual(time_observer_check.validate(events, runtime, 4242), 10)

    def test_process_changes_early_closures_and_missing_pep_evidence_are_rejected(self):
        for corruption in ['pid', 'fd', 'short_permit', 'short_deny', 'no_denials', 'no_pep', 'attribute_trigger']:
            with self.subTest(corruption=corruption):
                events, runtime = self.fixture()
                if corruption in ['pid', 'fd']:
                    events[-1][corruption] += 1
                elif corruption == 'short_permit':
                    events[-1]['unix_ns'] = 121_000_000_000
                elif corruption == 'short_deny':
                    events = [event for event in events if event['event'] != 'denied' or event['unix_ns'] < 112_000_000_000]
                    events[-2]['unix_ns'] = 112_000_000_000
                elif corruption == 'no_denials':
                    events = [event for event in events if event['event'] != 'denied']
                elif corruption == 'no_pep':
                    runtime = ''
                else:
                    runtime = runtime.replace('time:', 'attributes:')
                with self.assertRaises(ValueError):
                    time_observer_check.validate(events, runtime, 4242)

    def test_chapter_runs_two_cycles_and_cleans_up_observer(self):
        events, runtime = self.fixture()
        with tempfile.TemporaryDirectory(prefix='time chapter ') as directory:
            root = Path(directory)
            demo_scripts = root / 'scripts/demo'
            demo_scripts.mkdir(parents=True)
            (demo_scripts / 'time-observer-check.py').symlink_to(PROJECT / 'scripts/demo/time-observer-check.py')
            # The chapter integration uses prepared evidence; actual open FDs
            # are checked separately on Linux and in the privileged live test.
            (demo_scripts / 'time-observer.sh').write_text('''#!/usr/bin/env bash
set -eu
python3 - "$2" "$3" "$$" <<'PY_EVIDENCE'
import json, os, sys
from pathlib import Path
root = Path(sys.argv[1])
pid = int(sys.argv[3])
events = json.loads(os.environ['TEST_TIME_EVENTS'])
for event in events:
    event['pid'] = pid
(root / 'events.jsonl').write_text(''.join(json.dumps(event) + '\\n' for event in events))
with Path(sys.argv[2]).open('a') as log:
    log.write(os.environ['TEST_TIME_RUNTIME'].replace('pid=4242', f'pid={pid}'))
(root / 'state.json').write_text(json.dumps(dict(opens=2, revocations=2, denied=10)))
PY_EVIDENCE
exec sleep 20
''')
            target = root / 'protected file.txt'
            target.write_text('protected')
            (root / 'runtime.log').touch()
            script = '''set -Eeuo pipefail
original_project="$1"
source "$original_project/scripts/demo/runner.sh"
PROJECT_ROOT="$2"
demo_root="$2"
target="$demo_root/protected file.txt"
probe_pid=''
DEMO_TIMEOUT_SECONDS=1
trap stop_probe EXIT
chapter_start() { :; }
chapter_section() { :; }
pause_demo() { :; }
step() { [[ $# -eq 1 ]]; }
policy() { [[ "$1" == timed && "$2" == deny && "$3" == '    environment.time % 20 >= 10;' ]]; }
admin() { :; }
show_request() { :; }
show_decision() { :; }
alive() { :; }
generations() { printf '1 1\n'; }
wait_log() { grep -Fq "$1" "$demo_root/runtime.log"; }
remove_policy() { [[ "$1" == timed ]]; printf 'TIME_POLICY_REMOVED\n'; }
stat() { printf 'Device (Major:Minor): 8:2 | Inode: 12345\n'; }
run_chapter() { source "$original_project/scripts/demo/cases/09-fd-entzug-zeitgrenze.sh"; }
run_chapter
[[ -z "$probe_pid" ]]
'''
            result = subprocess.run(
                [shutil.which('bash'), '-c', script, 'test', str(PROJECT), directory],
                env={**os.environ, 'TEST_TIME_EVENTS': json.dumps(events), 'TEST_TIME_RUNTIME': runtime},
                capture_output=True, text=True, timeout=8,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('zwei FD-Entzüge; 10 verweigerte Öffnungsversuche', result.stdout)
            self.assertIn('TIME_POLICY_REMOVED', result.stdout)
            self.assertIn('protected', result.stdout)

    @unittest.skipUnless(Path('/proc/self/fd').is_dir(), 'Der Zeitbeobachter benötigt Linux /proc')
    def test_observer_opens_one_real_fd_and_keeps_it_in_its_own_process(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / 'protected file.txt'
            target.write_text('protected')
            with (root / 'observer.log').open('w') as output:
                process = subprocess.Popen(
                    [shutil.which('bash'), str(PROJECT / 'scripts/demo/time-observer.sh'),
                     str(target), directory, str(root / 'runtime.log')],
                    stdout=output, stderr=subprocess.STDOUT,
                )
                try:
                    deadline = time.monotonic() + 4
                    while not (root / 'state.json').exists() and time.monotonic() < deadline:
                        self.assertIsNone(process.poll(), (root / 'observer.log').read_text())
                        time.sleep(0.05)
                    state = json.loads((root / 'state.json').read_text())
                    self.assertEqual(state['opens'], 1)
                    self.assertEqual(state['revocations'], 0)
                    self.assertTrue(os.path.samefile(f'/proc/{process.pid}/fd/10', target))
                    time.sleep(1.1)
                    self.assertTrue(os.path.samefile(f'/proc/{process.pid}/fd/10', target))
                    events = [json.loads(line) for line in (root / 'events.jsonl').read_text().splitlines()]
                    self.assertEqual([event['event'] for event in events], ['opened'])
                    self.assertIn('FD 10 offen', (root / 'observer.log').read_text())
                finally:
                    process.terminate()
                    try:
                        process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()


class LauncherTests(unittest.TestCase):
    def run_launcher(self, with_tmux, build=False, git_status=0):
        with tempfile.TemporaryDirectory(prefix="demo test ") as directory:
            root = Path(directory)
            binaries = root / "bin"
            binaries.mkdir()
            commands = "bash cat chmod chown date dirname env flock grep head id ln ls mkdir mkfifo mktemp mount mv pgrep ps python3 readlink rm rmdir sleep stat sudo tail tee uname unshare wc".split()
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
                "git": '#!/bin/sh\nprintf "%s\\n" "$@" > "$GIT_CALL"\nexit "$GIT_STATUS"\n',
                "nix-shell": '''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
with open(os.environ['CALLS'], 'a') as log:
    log.write(json.dumps(sys.argv[1:]) + '\\n')
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
        assert command[4] == os.environ['DEMO_SUDO_BIN'], command
        assert '-n' not in command and '-v' not in command, command
    root = Path(command[command.index('--worker') + 1].rstrip(';'))
    Path(os.environ['DEMO_ROOT_CAPTURE']).write_text(str(root))
    (root / 'exit-status').write_text('0\\n')
''')
                (binaries / "tmux").chmod(0o755)
            environment = {**os.environ, "PATH": str(binaries), "CALLS": str(root / "calls"), "DEMO_ROOT_CAPTURE": str(root / "demo-root"),
                           "TAILS_PDP_BIN": str(demo_binary), "ADM_TOOL_BIN": str(demo_binary), "DEMO_SUDO_BIN": str(system_sudo),
                           "DEMO_ARTIFACT_PATH_FILE": str(root / "artifact-path")}
            environment.pop("TAILS_DEMO_NIX", None)
            environment.pop("TAILS_DEMO_UPDATE_ATTEMPTED", None)
            environment.update(GIT_CALL=str(root / 'git-call'), GIT_STATUS=str(git_status))
            try:
                terminal_log = root / 'terminal.log'
                arguments = [str(PROJECT / 'scripts/demo.sh'), '--auto']
                if build:
                    arguments.append('--build')
                status, timed_out = live.run_in_pty(arguments,
                                                  environment, terminal_log, timeout=20, grace=2)
                diagnostic = terminal_log.read_text(errors='replace')
                self.assertFalse(timed_out, f'Launcher-Test überschritt das Zeitlimit:\n{diagnostic}')
                self.assertEqual(status, 0, f'Launcher-Ausgabe:\n{diagnostic}')
                self.assertEqual((root / 'git-call').read_text().splitlines(),
                                 ['-C', str(PROJECT), 'pull', '--ff-only'])
                if git_status:
                    self.assertIn('Die Demo startet mit dem vorhandenen Stand.', diagnostic)
                if with_tmux:
                    self.assertEqual((root / 'artifact-path').read_text().strip(), (root / 'demo-root').read_text())
            finally:
                if (root / "demo-root").exists():
                    shutil.rmtree((root / "demo-root").read_text())
            return (root / "calls").read_text()

    def test_missing_programs_reexec_via_nix(self):
        arguments = json.loads(self.run_launcher(False))
        self.assertEqual(arguments[:8], ['--option', 'substitute', 'false', '--option', 'builders', '', '-j', '0'])
        self.assertEqual(arguments[8], str(PROJECT / "scripts/demo/shell.nix"))
        self.assertEqual(arguments[9], "--run")
        self.assertEqual(shlex.split(arguments[10]), ["bash", str(PROJECT / "scripts/demo.sh"), "--auto"])

    def test_failed_git_update_still_starts_demo(self):
        calls = [json.loads(line) for line in self.run_launcher(True, git_status=128).splitlines()]
        self.assertTrue(any('attach-session' in call for call in calls))

    def test_tmux_layout_and_worker_are_configured_before_attach(self):
        calls = [json.loads(line) for line in self.run_launcher(True).splitlines()]
        self.assertEqual(sum('split-window' in call for call in calls), 2)
        self.assertEqual(sum('respawn-pane' in call for call in calls), 1)
        worker_index = next(i for i, call in enumerate(calls) if 'respawn-pane' in call)
        attach_index = next(i for i, call in enumerate(calls) if 'attach-session' in call)
        self.assertLess(worker_index, attach_index)
        self.assertIn('kill-server', calls[-1])
        self.assertTrue(any('status-format[1]' in call and 'Legende:' in call[-1] for call in calls))

    def test_build_uses_local_nix_dependencies_and_offline_builder(self):
        calls = [json.loads(line) for line in self.run_launcher(True, build=True).splitlines()]
        build = next(call for call in calls if str(PROJECT / 'nix-config/shell.nix') in call)
        self.assertEqual(build[:8], ['--option', 'substitute', 'false', '--option', 'builders', '', '-j', '0'])
        command = build[build.index('--run') + 1]
        self.assertEqual(shlex.split(command), ['bash', str(PROJECT / 'scripts/demo/build.sh')])


class RequestViewTests(unittest.TestCase):
    def request(self, position='"engineer"', time_condition='none', alias=False,
                condition='subject.position == "engineer";'):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / 'protected.txt'
            target.write_text('protected')
            control = root / 'control.txt'
            control.write_text('control')
            metadata = target.stat()
            device = (os.major(metadata.st_dev) << 20) | os.minor(metadata.st_dev)
            identity = (device, metadata.st_ino)
            snapshot = (
                'generation policy=11 policy_bank_offset=256 attribute=8 attribute_bank=0\n'
                'FILE_OPEN_STREAM_POLICIES:\n'
                f'[0] enabled=1 legacy_condition={time_condition}\n'
                f'    {condition}\n'
                'ATTRIBUTES:\n'
                'system.defcon = 2\n'
                'subject:60001 subject.position = "unrelated"\n'
                f'resource:{device}:{metadata.st_ino} resource.classification = "internal"\n'
                f'resource:{device}:{control.stat().st_ino} resource.classification = "public"\n'
            )
            if position is not None:
                snapshot += f'subject:0 subject.position = {position}\n'
            if alias:
                linked = root / 'alias.txt'
                linked.hardlink_to(target)
                target = linked
            text = request_view.describe(snapshot, 'cat', '0', target, now=3661)
            device_line = f'resource.device == {device};'
            inode_line = f'resource.inode == {metadata.st_ino};'
            self.assertLess(text.index(device_line), text.index(inode_line))
            self.assertLess(text.index(inode_line), text.index('resource.path =='))
            self.assertIn(f'resource.path == {json.dumps(str(target), ensure_ascii=False)};', text)
            return text, identity

    def test_only_attributes_for_requested_subject_and_resource_are_shown(self):
        text, _ = self.request()
        self.assertIn('subject.uid == 0;', text)
        self.assertIn('action == "file_open";', text)

        self.assertIn('command == "cat";', text)
        self.assertIn('system.defcon == 2;', text)
        self.assertIn('subject.position == "engineer";', text)
        self.assertIn('resource.classification == "internal";', text)
        self.assertNotIn('unrelated', text)
        self.assertNotIn('public', text)
        self.assertIn('Policygeneration 11, Attributgeneration 8', text)
        self.assertIn('\n\nAttribute:\n', text)
        self.assertIn('\n\nMetadaten:\n', text)
        self.assertTrue(all(not line or line == line.lstrip() for line in text.splitlines()))

    def test_missing_attributes_are_detected_in_current_and_legacy_policy_output(self):
        for condition in ['subject.position == "engineer";',
                          'attribute_condition=subject.position == "engineer";',
                          'attribute_condition=subject.position Equal "engineer"']:
            with self.subTest(condition=condition):
                text, _ = self.request(position=None, condition=condition)
                self.assertIn('# subject.position: nicht vorhanden', text)

    def test_missing_and_numeric_attributes_keep_their_meaning(self):
        text, _ = self.request(position=None)
        self.assertIn('# subject.position: nicht vorhanden', text)
        self.assertNotIn('subject.position ==', text)
        text, _ = self.request(position='1')
        self.assertIn('subject.position == 1;', text)
        self.assertNotIn('subject.position == "1";', text)

    def test_hardlink_has_original_identity_and_resource_attributes(self):
        text, identity = self.request(alias=True)
        self.assertIn(f'resource.device == {identity[0]};', text)
        self.assertIn(f'resource.inode == {identity[1]};', text)
        self.assertNotIn('Dateiidentität:', text)
        self.assertIn('resource.classification == "internal";', text)

    def test_context_quotes_strings_without_creating_additional_statements(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'quoted"file.txt'
            target.write_text('protected')
            command = 'cat";\nother'
            snapshot = 'generation policy=1 attribute=2\nATTRIBUTES:\n'
            text = request_view.describe(snapshot, command, '0', target)
            for field, expected in [('command', command), ('resource.path', str(target))]:
                line = next(line.strip() for line in text.splitlines()
                            if line.strip().startswith(field + ' == '))
                self.assertTrue(line.endswith(';'))
                self.assertEqual(json.loads(line[len(field + ' == '):-1]), expected)

    def test_time_conditions_show_explicit_system_time_snapshot(self):
        for condition in ('Time % 4294967296 GreaterThanOrEqual 10', 'Hour GreaterThanOrEqual 0'):
            with self.subTest(condition=condition):
                text, _ = self.request(time_condition=condition)
                self.assertIn('Momentaufnahme der Systemzeit', text)
                self.assertIn('environment.utc.hour == 1;', text)
                self.assertIn('environment.utc.minute == 1;', text)
                self.assertIn('environment.utc.second == 1;', text)
                self.assertIn('environment.time == 3661;', text)


class PresentationTests(unittest.TestCase):
    def test_run_cmd_prints_exact_command_and_preserves_failure_status(self):
        commands = [('echo $UID', 0, str(os.getuid())), ('exit 7', 7, None)]
        for command, expected_status, output in commands:
            with self.subTest(command=command):
                result = subprocess.run(
                    [shutil.which('bash'), '-c', 'source "$1"; run_cmd "$2"', 'test',
                     str(PROJECT / 'scripts/demo/runner.sh'), command],
                    capture_output=True, text=True,
                )
                self.assertEqual(result.returncode, expected_status, result.stderr)
                self.assertIn('$ ' + command + '\n', result.stdout)
                if output is not None:
                    self.assertTrue(result.stdout.endswith(output + '\n'))

    def test_run_cmd_handles_quoted_paths_as_literal_filenames(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'file with $dollar and spaces.txt'
            target.write_text('actual file contents\n')
            command = 'cat ' + shlex.quote(str(target))
            result = subprocess.run(
                [shutil.which('bash'), '-c', 'source "$1"; run_cmd "$2"', 'test',
                 str(PROJECT / 'scripts/demo/runner.sh'), command],
                capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('$ ' + command + '\n', result.stdout)
            self.assertTrue(result.stdout.endswith('actual file contents\n'))

    def test_decision_block_shows_actual_result_and_detects_mismatch(self):
        script = '''set -Eeuo pipefail
source "$RUNNER"
demo_root="$TEST_ROOT"
show_decision "$EXPECTED" "$ACTUAL" "$PROJECT_ROOT/demo/files/protected.txt"
'''
        for expected, actual in [('allow', 'allow'), ('deny', 'deny'), ('deny', 'allow')]:
            with self.subTest(expected=expected, actual=actual), tempfile.TemporaryDirectory() as directory:
                result = subprocess.run([shutil.which('bash'), '-c', script],
                                        env={**os.environ, 'RUNNER': str(PROJECT / 'scripts/demo/runner.sh'),
                                             'PROJECT_ROOT': str(PROJECT), 'TEST_ROOT': directory,
                                             'EXPECTED': expected, 'ACTUAL': actual},
                                        capture_output=True, text=True)
                label = 'Permit' if actual == 'allow' else 'Deny'
                self.assertIn(f'Decision: {label}', result.stdout)
                self.assertIn(f'resource.path == {json.dumps(str(PROJECT / "demo/files/protected.txt"), ensure_ascii=False)};', result.stdout)
                self.assertNotIn('Observed Enforcement:', result.stdout)
                self.assertNotIn('Expected Decision:', result.stdout)
                self.assertEqual(result.returncode == 0, actual == expected)
                self.assertEqual('[Demo-Prüfung] OK:' in result.stdout, actual == expected)

    def test_substep_needs_both_read_and_execution_confirmation(self):
        script = '''set -Eeuo pipefail
source "$RUNNER"
DEMO_AUTO="$AUTO"
demo_current_chapter='3. Policy-Lebenszyklus'
printf 'vorheriges Ergebnis\\n'
step 'Deny-Policy ergänzen'
printf 'AKTION_AUSGEFUEHRT\\n'
'''
        for automatic, entered, executes in [('0', '', False), ('0', '\n', False),
                                             ('0', '\n\n', True), ('1', '', True)]:
            with self.subTest(automatic=automatic, entered=repr(entered)):
                result = subprocess.run([shutil.which('bash'), '-c', script], input=entered,
                                        env={**os.environ, 'RUNNER': str(PROJECT / 'scripts/demo/runner.sh'), 'AUTO': automatic},
                                        text=True, capture_output=True)
                self.assertEqual('AKTION_AUSGEFUEHRT' in result.stdout, executes, result.stderr)

    def test_substep_rejects_accidentally_appended_commands(self):
        script = 'source "$1"; DEMO_AUTO=1; step "Policy veröffentlichen" policy scoped deny'
        result = subprocess.run(
            [shutil.which('bash'), '-c', script, 'test', str(PROJECT / 'scripts/demo/runner.sh')],
            capture_output=True, text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('nachfolgende Befehle in eine eigene Zeile', result.stderr)

    def test_native_fd_check_keeps_state_validation_and_omits_extra_authorization_output(self):
        script = '''set -Eeuo pipefail
source "$1"
probe_pid=$$
DEMO_TIMEOUT_SECONDS=0
probe_state_is() { [[ "$TEST_PROBE_STATE" == closed ]]; }
alive() { :; }
show_request() { printf 'CONTEXT\n'; }
show_decision() { printf 'DECISION\n'; }
observe() { printf 'OBSERVED\n'; }
target=/protected.txt
safe=/control.txt
expect_revoked "$2"
'''
        for mode, state in [('--native', 'closed'), ('--native', 'open'), ('', 'closed')]:
            with self.subTest(mode=mode, state=state):
                result = subprocess.run(
                    [shutil.which('bash'), '-c', script, 'test', str(PROJECT / 'scripts/demo/runner.sh'), mode],
                    env={**os.environ, 'TEST_PROBE_STATE': state}, capture_output=True, text=True,
                )
                if state == 'open':
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn('FD-Entzug ausgeblieben', result.stderr)
                else:
                    self.assertEqual(result.returncode, 0, result.stderr)
                    if mode == '--native':
                        self.assertEqual(result.stdout, '')
                    else:
                        self.assertEqual(result.stdout.count('CONTEXT'), 2)
                        self.assertEqual(result.stdout.count('DECISION'), 2)

    def test_first_chapter_checks_runtime_and_maps_before_reading_file(self):
        for missing_map in [False, True]:
            with self.subTest(missing_map=missing_map), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                pins = root / 'pins'
                pins.mkdir()
                for name in ['POLICY_GENERATION', 'ATTRIBUTE_GENERATION', 'FILE_OPEN_STATIC_POLICIES',
                             'FILE_OPEN_STREAM_POLICIES', 'CURRENT_TIME', 'ATTRIBUTES']:
                    if not (missing_map and name == 'CURRENT_TIME'):
                        (pins / name).touch()
                (root / 'protected file.txt').write_text('CHAPTER_ONE_CONTENT\n')
                runtime = root / 'runtime.sh'
                runtime.write_text('#!/usr/bin/env bash\nprintf "Kernel debug logging mode=Deny\\nWaiting for Ctrl-C\\nscan completed\\n"\nexec sleep 20\n')
                runtime.chmod(0o755)
                script = '''set -Eeuo pipefail
source "$1/scripts/demo/runner.sh"
PROJECT_ROOT="$1"
demo_root="$2"
pin_dir="$demo_root/pins"
target="$demo_root/protected file.txt"
safe="$demo_root/control.txt"
TAILS_PDP_BIN="$demo_root/runtime.sh"
DEMO_TIMEOUT_SECONDS=3
runtime_pid=''
trap 'if [[ -n "$runtime_pid" ]]; then kill "$runtime_pid" 2>/dev/null || true; wait "$runtime_pid" 2>/dev/null || true; fi' EXIT
chapter_start() { :; }
chapter_section() { :; }
pause_demo() { :; }
start_kernel_trace() { :; }
alive() { kill -0 "$runtime_pid" 2>/dev/null; }
admin() { :; }
show_request() { :; }
show_decision() { return 99; }
command_access_is() { return 99; }
explain() { :; }
stat() { printf 'Device (Major:Minor): 8:2 | Inode: 12345\n'; }
run_chapter() { source "$PROJECT_ROOT/scripts/demo/cases/01-runtime-start.sh"; }
run_chapter
'''
                result = subprocess.run([shutil.which('bash'), '-c', script, 'test', str(PROJECT), directory],
                                        capture_output=True, text=True, timeout=6)
                if missing_map:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn('Map fehlt: CURRENT_TIME', result.stderr)
                    self.assertNotIn('CHAPTER_ONE_CONTENT', result.stdout)
                else:
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn('CHAPTER_ONE_CONTENT', result.stdout)

    def test_static_policy_chapter_runs_visible_commands_and_checks_denials(self):
        script = '''set -Eeuo pipefail
source "$1/scripts/demo/runner.sh"
target=/example/protected.txt
safe=/example/control.txt
PROJECT_ROOT=/example
demo_root="$2"
comparison_uid=1000
deny_error="$3"
active=0 shown=0
chapter_start() { :; }
chapter_section() { :; }
pause_demo() { :; }
explain() { :; }
step() { [[ $# -eq 1 ]]; }
id() { if [[ "$1" == -un ]]; then printf 'demo-test\n'; else printf '1000\n'; fi; }
stat() { printf 'Device (Major:Minor): 8:2 | Inode: 12345\n'; }
cat() {
    if [[ "$active" == 1 && "${comparison:-0}" == 0 && "$1" != "$safe" ]]; then
        [[ "$shown" == 1 ]]
        printf 'cat: %s: %s\n' "$1" "$deny_error" >&2
        return 1
    fi
    printf 'CAT_READ %s\n' "$1"
}
head() { printf 'HEAD_READ %s\n' "$1"; }
sudo() { [[ "$1" == -u && "$2" == demo-test && "$3" == -- ]]; shift 3; comparison=1 "$@"; }
policy() { [[ "$1" == scoped && "$2" == deny ]]; active=1; printf 'POLICY_ACTIVATED\n'; }
admin() { if [[ "$active" == 1 ]]; then shown=1; printf 'ACTIVE_POLICY_SHOWN\n'; fi; }
show_request() { :; }
show_decision() { printf 'Unerwarteter show_decision-Aufruf\n' >&2; return 99; }
remove_policy() { active=0; printf 'POLICY_REMOVED\n'; }
source "$1/scripts/demo/cases/02-statische-policies.sh"
'''
        for error in ['Operation not permitted', 'Permission denied', 'No such file or directory']:
            with self.subTest(error=error), tempfile.TemporaryDirectory() as directory:
                result = subprocess.run(
                    [shutil.which('bash'), '-c', script, 'test', str(PROJECT), directory, error],
                    capture_output=True, text=True,
                )
                if error != 'Operation not permitted':
                    self.assertNotEqual(result.returncode, 0)
                    self.assertNotIn('POLICY_REMOVED', result.stdout)
                    continue
                self.assertEqual(result.returncode, 0, result.stderr)
                baseline, rest = result.stdout.split('POLICY_ACTIVATED', 1)
                self.assertEqual(baseline.count('CAT_READ'), 2)
                self.assertLess(rest.index('ACTIVE_POLICY_SHOWN'), rest.index('$ cat /example/protected.txt'))
                self.assertEqual(result.stderr.count('Operation not permitted'), 2)
                self.assertNotIn('Authorization Decision', result.stdout)
                self.assertIn('$ head /example/protected.txt', rest)
                self.assertIn('$ sudo -u demo-test -- cat /example/protected.txt', rest)
                self.assertIn('$ cat /example/control.txt', rest)
                self.assertIn('$ cat /example/demo/files/alias.txt', rest)
                self.assertIn('CAT_READ /example/protected.txt', rest.split('POLICY_REMOVED', 1)[1])

    def test_following_chapters_run_commands_and_preserve_denial_checks(self):
        scenarios = {
            '03-policy-lebenszyklus.sh': ['allow', 'deny', 'allow'],
            '04-systemattribut.sh': ['allow', 'deny', 'allow'],
            '05-subjekt-und-ressourcenattribute.sh': ['deny', 'allow', 'deny', 'allow', 'deny', 'allow', 'allow', 'deny'],
            '06-ungueltige-updates.sh': [],
            '07-fd-entzug-policy.sh': [],
            '08-fd-entzug-attribut.sh': [],
            '10-utc-zeitbedingungen.sh': ['allow', 'deny'],
        }
        script = '''set -Eeuo pipefail
source "$1/scripts/demo/runner.sh"
PROJECT_ROOT="$1"
demo_root="$2"
chapter="$3"
deny_error="$4"
shift 4
expectations=("$@")
request_index=0
current=''
target='/example/protected file.txt'
safe='/example/control.txt'
policy_dir="$demo_root/policies"
attribute_dir="$demo_root/attributes"
probe_dir="$demo_root"
mkdir -p "$attribute_dir" "$policy_dir"
: > "$demo_root/runtime.log"
printf '{"unix_ns":9999999999999999999}' > "$probe_dir/state.json"
chapter_start() { :; }
chapter_section() { :; }
pause_demo() { :; }
explain() { :; }
observe() { :; }
step() { [[ $# -eq 1 ]]; }
policy() {
    if [[ "$chapter" == 07-* ]]; then printf 'NATIVE_POLICY_PUBLISHED\n'; fi
}
attribute() {
    mkdir -p "$(dirname "$attribute_dir/$1")"
    printf '%s\\n' "$2" > "$attribute_dir/$1"
}
remove_policy() { [[ "$1" != broken ]]; }
admin() { printf 'ADMIN_ACTIVE\n'; }
generations() { printf '1 1\n'; }
wait_log() {
    if [[ "$chapter" == 07-* ]]; then
        [[ "$1" == 'USERSPACE_PEP closed pid=4242 fd='* ]]
        printf 'PEP_CLOSE_CONFIRMED\n'
    fi
}
mv() {
    [[ "$1" == -f && "$2" == -- && "$3" == "$attribute_dir/system.attributes.tmp" && "$4" == "$attribute_dir/system.attributes" ]]
    command mv "$@"
    printf '%s\\n' "$(< "$attribute_dir/system.attributes")" >> "$demo_root/attribute-renames"
}
wait_generation() {
    [[ "$1" == attribute && -f "$demo_root/attribute-renames" ]]
    [[ "$(< "$attribute_dir/system.attributes")" == 'defcon = 2' || "$(< "$attribute_dir/system.attributes")" == 'defcon = 5' ]]
    [[ ! -e "$attribute_dir/system.attributes.tmp" ]]
}
show_policy_context() { :; }
publish() { : > "$1"; while IFS= read -r line; do printf '%s\\n' "$line" >> "$1"; done; }
start_probe() {
    if [[ "$chapter" == 07-* ]]; then [[ "$1" == --native ]]; fi
    probe_pid=4242
    printf 'PROBE_STARTED\n'
}
ls() { [[ "$1" == -l && "$2" == /proc/4242/fd ]]; printf 'PROC_FD_LIST\n'; }
assert_probe_identity() { :; }
expect_revoked() {
    if [[ "$chapter" == 07-* ]]; then [[ "$1" == --native ]]; fi
    printf 'PROBE_REVOKED\n'
}
stop_probe() { :; }
show_request() {
    [[ "$1" == cat && "$2" == "$UID" && "$3" == "$target" ]]
    current="${expectations[$request_index]}"
    request_index=$((request_index + 1))
}
stat() { [[ "$3" == "$target" ]]; printf 'Device (Major:Minor): 8:2 | Inode: 12345\n'; }
cat() {
    if [[ "$1" == "$attribute_dir/"* ]]; then
        printf '%s\\n' "$(< "$1")"
        return
    fi
    [[ "$1" == "$target" ]]
    if [[ "$current" == deny ]]; then
        printf 'cat: %s: %s\n' "$1" "$deny_error" >&2
        return 1
    fi
    printf 'PROTECTED_CONTENT\n'
}
show_decision() {
    [[ "$1" == "$current" && "$2" == "$current" && "$3" == "$target" ]]
    printf 'CHECKED %s\n' "$current"
}
run_chapter() { source "$PROJECT_ROOT/scripts/demo/cases/$chapter"; }
run_chapter
[[ "$request_index" == "${#expectations[@]}" ]]
'''
        for chapter, expected in scenarios.items():
            for error in ['Operation not permitted', 'Permission denied', 'No such file or directory']:
                if error != 'Operation not permitted' and 'deny' not in expected:
                    continue
                with self.subTest(chapter=chapter, error=error), tempfile.TemporaryDirectory() as directory:
                    result = subprocess.run(
                        [shutil.which('bash'), '-c', script, 'test', str(PROJECT), directory, chapter, error, *expected],
                        capture_output=True, text=True,
                    )
                    if error != 'Operation not permitted':
                        self.assertNotEqual(result.returncode, 0)
                        self.assertNotIn('CHECKED deny', result.stdout)
                        continue
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    system_updates = {
                        '04': ['defcon = 2', 'defcon = 5'],
                        '05': ['defcon = 2'],
                        '06': ['defcon = 9', 'defcon = 5'],
                        '08': ['defcon = 2'],
                    }.get(chapter[:2])
                    if system_updates is not None:
                        self.assertEqual((Path(directory) / 'attribute-renames').read_text().splitlines(), system_updates)
                        self.assertEqual(result.stdout.count('$ mv -f -- '), len(system_updates))
                    if chapter.startswith('07-'):
                        self.assertEqual(result.stdout.count('PROC_FD_LIST'), 2)
                        self.assertEqual(result.stdout.count('PEP_CLOSE_CONFIRMED'), 3)
                        self.assertLess(result.stdout.index('PROC_FD_LIST'), result.stdout.index('NATIVE_POLICY_PUBLISHED'))
                        self.assertLess(result.stdout.index('NATIVE_POLICY_PUBLISHED'), result.stdout.index('PROBE_REVOKED'))
                        self.assertGreater(result.stdout.rindex('PROC_FD_LIST'), result.stdout.rindex('PEP_CLOSE_CONFIRMED'))
                        self.assertNotIn('CHECKED ', result.stdout)
                    if chapter.startswith('06-'):
                        self.assertIn('$ rm -- ', result.stdout)
                        self.assertFalse((Path(directory) / 'policies/broken.policy').exists())
                        self.assertEqual(result.stdout.count('ADMIN_ACTIVE'), 7)
                        self.assertNotIn('PROTECTED_CONTENT', result.stdout)
                        self.assertNotIn('CHECKED ', result.stdout)
                    if chapter.startswith('05-'):
                        for relative, content in [
                            ('system.attributes', 'defcon = 2'),
                            ('subjects/0.attributes', 'position = "engineer"'),
                            ('resources' + '/example/protected file.txt.attributes', 'classification = "internal"'),
                        ]:
                            path = str(Path(directory) / 'attributes' / relative)
                            lines = result.stdout.splitlines()
                            index = next(i for i, line in enumerate(lines)
                                         if line.startswith('$ cat ') and shlex.split(line[2:]) == ['cat', path])
                            self.assertEqual(lines[index + 1], content)
                    self.assertEqual(result.stdout.count('$ echo $UID'), len(expected))
                    self.assertEqual(result.stdout.count('$ cat /example/protected\\ file.txt'), len(expected))
                    if chapter[:2] in ('03', '04'):
                        self.assertNotIn('CHECKED ', result.stdout)
                        self.assertNotIn('Authorization Decision', result.stdout)
                        self.assertEqual(result.stdout.count('PROTECTED_CONTENT'), expected.count('allow'))
                        self.assertEqual(result.stderr.count('Operation not permitted'), expected.count('deny'))
                    else:
                        self.assertEqual([line for line in result.stdout.splitlines() if line.startswith('CHECKED ')],
                                         ['CHECKED ' + value for value in expected])

    def test_publication_shows_content_but_keeps_internal_command_in_log(self):
        with tempfile.TemporaryDirectory(prefix='demo-publication-', dir=PROJECT) as directory:
            root = Path(directory)
            (root / 'policies').mkdir()
            policy_text = ('policy "example"\ndeny\n    action == "file_open";\n'
                           '    resource.path == "/example.txt";\n    command == "cat";\n'
                           '    subject.uid == 60001;\n    system.defcon <= 2;\n')
            script = '''set -Eeuo pipefail
source "$RUNNER"
demo_root="$TEST_ROOT"
policy_dir="$demo_root/policies"
printf '%s' "$POLICY_TEXT" | publish "$policy_dir/example.policy"
show_policy_context
'''
            result = subprocess.run([shutil.which('bash'), '-c', script], cwd=PROJECT,
                                    env={**os.environ, 'RUNNER': str(PROJECT / 'scripts/demo/runner.sh'),
                                         'PROJECT_ROOT': str(PROJECT), 'TEST_ROOT': directory,
                                         'POLICY_TEXT': policy_text},
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('Folgende Policy veröffentlicht', result.stdout)
            self.assertEqual(result.stdout.count(policy_text), 2)
            self.assertNotIn('publish-config.sh', result.stdout)
            self.assertNotIn('Published', result.stdout)
            self.assertEqual((root / 'policies/example.policy').read_text(), policy_text)
            self.assertIn('publish-config.sh', (root / 'publication.log').read_text())


class CommandAccessTests(unittest.TestCase):
    def check_access(self, expected, mode, command='cat', uid='60001'):
        with tempfile.TemporaryDirectory(prefix='real command ') as directory:
            root = Path(directory)
            binaries = root / 'bin'
            binaries.mkdir()
            target = root / 'protected file.txt'
            target.write_text('sichtbarer Dateiinhalt\n')
            stub = '''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
if Path(sys.argv[0]).name == 'id':
    assert sys.argv[1:] == ['-un', '60001'], sys.argv
    print('demo-test')
    raise SystemExit(0)
if Path(sys.argv[0]).name == 'stat':
    assert sys.argv[1:3] == ['-Lc', 'Device (Major:Minor): %Hd:%Ld | Inode: %i'], sys.argv
    metadata = os.stat(sys.argv[3])
    print(f'Device (Major:Minor): {os.major(metadata.st_dev)}:{os.minor(metadata.st_dev)} | Inode: {metadata.st_ino}')
    raise SystemExit(0)
if Path(sys.argv[0]).name == 'sudo':
    assert sys.argv[1:4] == ['-u', 'demo-test', '--'], sys.argv
    Path(os.environ['INVOCATION']).write_text(json.dumps(sys.argv[1:]))
    if os.environ['ACCESS_MODE'] == 'sudo-error':
        print('sudo: permission denied', file=sys.stderr)
        raise SystemExit(1)
    if sys.argv[4:] == ['id', '-u']:
        print('60001')
        raise SystemExit(0)
    os.execvp(sys.argv[4], sys.argv[4:])
if sys.argv[-1] == os.environ['TEST_TARGET'] and os.environ['ACCESS_MODE'] != 'allow':
    error = {'deny': 'Operation not permitted', 'dac': 'Permission denied', 'missing': 'No such file or directory'}[os.environ['ACCESS_MODE']]
    print('cat: ' + sys.argv[-1] + ': ' + error, file=sys.stderr)
    raise SystemExit(1)
os.execv(os.environ['REAL_CAT'], [os.environ['REAL_CAT'], *sys.argv[1:]])
'''
            for name in ('sudo', 'id', 'stat', 'cat'):
                path = binaries / name
                path.write_text(stub)
                path.chmod(0o755)
            environment = {**os.environ, 'PATH': str(binaries) + os.pathsep + os.environ['PATH'],
                           'REAL_CAT': shutil.which('cat'), 'ACCESS_MODE': mode,
                           'TEST_TARGET': str(target), 'TEST_ROOT': directory,
                           'PROJECT_ROOT': str(PROJECT),
                           'RUNNER': str(PROJECT / 'scripts/demo/runner.sh'),
                           'TEST_EXPECTED': expected, 'TEST_COMMAND': command, 'TEST_UID': uid,
                           'INVOCATION': str(root / 'invocation'), 'DEMO_SUDO_BIN': str(binaries / 'sudo')}
            script = '''set -Eeuo pipefail
source "$RUNNER"
alive() { return 0; }
admin() { printf 'generation policy=1 attribute=1\nATTRIBUTES:\nsystem.defcon = 5\n'; }
demo_root="$TEST_ROOT"
target="$TEST_TARGET"
command_access_is "$TEST_EXPECTED" "$TEST_COMMAND" "$TEST_UID"
'''
            result = subprocess.run([shutil.which('bash'), '-c', script], env=environment,
                                    capture_output=True, text=True)
            if uid == '-':
                self.assertFalse((root / 'invocation').exists(), result.stdout + result.stderr)
                self.assertIn('$ echo $UID\n', result.stdout)
                self.assertIn(f'subject.uid == {os.getuid()};', result.stdout)
                self.assertNotIn('sudo -u', result.stdout)
                self.assertIn('$ cat ', result.stdout)
            else:
                self.assertTrue((root / 'invocation').exists(), result.stdout + result.stderr)
                expected_command = ['id', '-u'] if mode == 'sudo-error' else [command, str(target)]
                self.assertEqual(json.loads((root / 'invocation').read_text()),
                                 ['-u', 'demo-test', '--', *expected_command])
            return result

    def test_current_uid_uses_plain_cat_without_sudo(self):
        result = self.check_access('allow', 'allow', uid='-')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('sichtbarer Dateiinhalt', result.stdout)
        self.assertRegex(result.stdout, r'\$ echo \$UID\n\d+\n\n\$ stat ')
        self.assertRegex(result.stdout, r'Device \(Major:Minor\): \d+:\d+ \| Inode: \d+\n\n\$ cat ')
        self.assertNotIn('Dateizugriff durch das Programm', result.stdout)

    def test_real_cat_and_head_show_file_contents(self):
        for command in ('cat', 'head'):
            with self.subTest(command=command):
                result = self.check_access('allow', 'allow', command)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn('sichtbarer Dateiinhalt', result.stdout)
                self.assertNotIn('→ stdout]', result.stdout)

    def test_expected_deny_is_verified(self):
        result = self.check_access('deny', 'deny')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Operation not permitted', result.stdout)
        self.assertIn('Decision: Deny', result.stdout)
        self.assertNotIn('Aufruf → stderr]', result.stdout)
        self.assertIn('Operation not permitted', result.stdout)

    def test_other_errors_and_unexpected_success_are_not_denials(self):
        for mode in ('dac', 'missing', 'sudo-error', 'allow'):
            with self.subTest(mode=mode):
                result = self.check_access('deny', mode)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn('[Demo-Prüfung] OK:', result.stdout)


class PaneSupervisorTests(unittest.TestCase):
    def test_early_failure_is_logged_and_returns_status(self):
        with tempfile.TemporaryDirectory(prefix='pane failure ') as directory:
            root = Path(directory)
            command = [shutil.which('bash'), str(PROJECT / 'scripts/demo/pane.sh'), directory, '1',
                       shutil.which('python3'), '-c',
                       'import os,sys; print("stdout_tty", os.isatty(1)); print("sudo: a password is required", file=sys.stderr); sys.exit(9)']
            status, timed_out = live.run_in_pty(command, os.environ, root / 'terminal.log', timeout=5)
            self.assertFalse(timed_out)
            self.assertEqual(status, 9)
            self.assertEqual((root / 'exit-status').read_text().strip(), '9')
            self.assertIn('sudo: a password is required', (root / 'startup.log').read_text())
            self.assertIn('stdout_tty True', (root / 'terminal.log').read_text())

    def test_interactive_early_failure_waits_for_enter(self):
        with tempfile.TemporaryDirectory(prefix='pane interactive ') as directory:
            root = Path(directory)
            command = [shutil.which('bash'), str(PROJECT / 'scripts/demo/pane.sh'), directory, '0',
                       shutil.which('python3'), '-c', 'raise SystemExit(7)']
            _, timed_out = live.run_in_pty(command, os.environ, root / 'terminal.log', timeout=1, grace=1)
            self.assertTrue(timed_out, 'Startfehler muss bis zur Eingabe sichtbar bleiben.')
            self.assertIn('Enter: tmux-Demo schließen', (root / 'terminal.log').read_text())
            self.assertEqual((root / 'exit-status').read_text().strip(), '7')


class OfflineBuildTests(unittest.TestCase):
    def run_build(self, missing_toolchain=False, missing_sources=False):
        with tempfile.TemporaryDirectory(prefix='offline build ') as directory:
            root = Path(directory)
            binaries = root / 'bin'
            binaries.mkdir()
            for name in ('dirname', 'python3'):
                (binaries / name).symlink_to(shutil.which(name))
            core = root / 'sysroot/lib/rustlib/src/rust/library/core'
            core.mkdir(parents=True)
            if not missing_sources:
                (core / 'Cargo.toml').write_text('[package]\nname="core"\n')
                shutil.copyfile(PROJECT / 'nix-config/ebpf-sysroot/Cargo.lock', core.parent / 'Cargo.lock')
            stub = '''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
name = Path(sys.argv[0]).name
args = sys.argv[1:]
with open(os.environ['CALLS'], 'a') as log:
    log.write(json.dumps([name, args, os.environ.get('CARGO_NET_OFFLINE'), os.environ.get('RUSTUP_TOOLCHAIN')]) + '\\n')
if name == 'rustup':
    if os.environ.get('RUSTUP_AUTO_INSTALL') != '0': raise SystemExit(96)
    if args[:1] != ['run']: raise SystemExit(95)
    if os.environ['MISSING_TOOLCHAIN'] == '1': raise SystemExit(19)
    print(os.environ['SYSROOT'] if args[-2:] == ['--print', 'sysroot'] else 'rustc test')
elif name == 'bpf-linker': print('bpf-linker 0.9.15')
'''
            for name in ('rustup', 'cargo', 'bpf-linker'):
                path = binaries / name
                path.write_text(stub)
                path.chmod(0o755)
            environment = {**os.environ, 'RUSTUP_AUTO_INSTALL': '1', 'PATH': str(binaries), 'CALLS': str(root / 'calls'),
                           'SYSROOT': str(root / 'sysroot'), 'MISSING_TOOLCHAIN': str(int(missing_toolchain))}
            result = subprocess.run([shutil.which('bash'), str(PROJECT / 'scripts/demo/build.sh')],
                                    env=environment, capture_output=True, text=True)
            calls = [json.loads(line) for line in (root / 'calls').read_text().splitlines()]
            return result, calls

    def test_offline_build_uses_frozen_sources_and_pinned_tools(self):
        result, calls = self.run_build()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls[-1][0:2], ['cargo', ['build', '--frozen', '--release', '--bin', 'tails-pdp', '--bin', 'tails-pdp-admintool']])
        self.assertTrue(all(call[2] == 'true' for call in calls))
        self.assertTrue(all(call[3] == (PROJECT / 'nix-config/rust-toolchain').read_text().strip() for call in calls))
        self.assertEqual([call[1][1] for call in calls if call[0] == 'rustup'][:2],
                         [(PROJECT / 'nix-config/rust-toolchain').read_text().strip(),
                          (PROJECT / 'nix-config/ebpf-toolchain').read_text().strip()])

    def test_missing_toolchain_stops_without_installing_or_building(self):
        result, calls = self.run_build(missing_toolchain=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('es wird nichts heruntergeladen', result.stderr)
        self.assertEqual([call[0] for call in calls], ['rustup'])

    def test_missing_rust_sources_stops_before_cargo(self):
        result, calls = self.run_build(missing_sources=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('rust-src', result.stderr)
        self.assertNotIn('cargo', [call[0] for call in calls])


class VendorSourceTests(unittest.TestCase):
    def test_missing_and_changed_sources_are_detected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            crate = root / 'example-1.0'
            crate.mkdir()
            source = crate / 'source.rs'
            source.write_bytes(b'original')
            (crate / '.cargo-checksum.json').write_text(json.dumps({
                'files': {'source.rs': hashlib.sha256(b'original').hexdigest()}}))
            self.assertEqual(vendor_check.verify(root), (1, []))
            source.write_bytes(b'changed')
            self.assertIn('Abweichende Vendor-Prüfsumme', vendor_check.verify(root)[1][0])
            source.unlink()
            self.assertIn('Fehlende Vendor-Datei', vendor_check.verify(root)[1][0])

    def test_repository_sources_match_all_checksums(self):
        count, errors = vendor_check.verify(PROJECT / 'vendor')
        self.assertGreater(count, 0)
        self.assertEqual(errors, [])
        self.assertEqual(vendor_check.verify_sysroot(PROJECT / 'vendor', PROJECT / 'nix-config/ebpf-sysroot/registry.json'), [])

    def test_missing_entire_sysroot_crate_is_detected(self):
        with tempfile.TemporaryDirectory() as directory:
            errors = vendor_check.verify_sysroot(Path(directory), PROJECT / 'nix-config/ebpf-sysroot/registry.json')
            self.assertTrue(any('rustc-literal-escaper-0.0.7' in error for error in errors))

    def test_wrong_installed_sysroot_lock_is_detected(self):
        with tempfile.TemporaryDirectory() as directory:
            lock = Path(directory) / 'Cargo.lock'
            lock.write_text('wrong version')
            errors = vendor_check.verify_sysroot(PROJECT / 'vendor', PROJECT / 'nix-config/ebpf-sysroot/registry.json', lock)
            self.assertTrue(any('rust-src passt nicht' in error for error in errors))


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
            (fixture / 'kernel.log').write_text('[Kernelspace-PEP] cat-42: file_open final=deny\n')
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
            with self.assertRaisesRegex(AssertionError, 'Deny Decision des Kernelspace-PEP'):
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
                self.assertIn('[Kernelspace-PEP] new: file_open final=deny', output)
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

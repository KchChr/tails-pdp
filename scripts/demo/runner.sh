#!/usr/bin/env bash
# Sourced by demo.sh --isolated-worker. The commented demo chapters are in
# demo_worker below; helpers implement publication, observation and assertions.

# Initialise before the worker redirects stdout through tee. Colour is a display
# concern only; raw admin polling and helper return values remain undecorated.
init_demo_colors() {
    color_reset='' color_heading='' color_section='' color_command=''
    color_output='' color_config='' color_success='' color_error='' color_prompt=''
    if [[ -t 1 && "${TERM:-dumb}" != dumb && -z "${NO_COLOR:-}" ]]; then
        color_reset=$'\033[0m'
        color_heading=$'\033[1;36m'
        color_section=$'\033[1m'
        color_command=$'\033[93m'
        color_output=$'\033[94m'
        color_config=$'\033[95m'
        color_success=$'\033[92m'
        color_error=$'\033[91m'
        color_prompt=$'\033[1;93m'
    fi
}
init_demo_colors

fail() { printf '\n%sFEHLER: %s%s\n' "$color_error" "$*" "$color_reset" >&2; return 1; }
alive() {
    local state
    if [[ -n "${kernel_trace_pid:-}" ]]; then
        state="$(ps -o stat= -p "$kernel_trace_pid")" || return 1
        [[ -n "$state" && "$state" != *Z* ]] || return 1
    fi
    state="$(ps -o stat= -p "$runtime_pid")" || return 1
    [[ -n "$state" && "$state" != *Z* ]]
}
observe() { printf '%s[Demo-Prüfung] %s%s\n' "$color_success" "$*" "$color_reset" | tee -a "$demo_root/observer.log"; }
pause_demo() {
    if [[ "$DEMO_AUTO" == 0 ]]; then
        read -r -p "$color_prompt${1:-Enter: ausführen | Strg+C: abbrechen }$color_reset" _
    fi
}
chapter() {
    # Leave the previous step's results visible until the presenter advances.
    # The first chapter has no preceding results; the last uses the close prompt.
    if [[ "${demo_chapter_started:-0}" == 1 ]]; then
        pause_demo 'Enter: zum nächsten Schritt | Strg+C: abbrechen '
    fi
    demo_chapter_started=1
    demo_current_chapter="$1"
    # Clear the current pane and move the cursor home, like clear. Keep the
    # scrollback and transcript; this needs no additional external command.
    printf '\033[2J\033[H'
    printf '\n%s%s%s\n' "$color_heading" "$1" "$color_reset"
    printf '\n%sAusgangslage:%s\n  %s\n' "$color_section" "$color_reset" "$2"
    # Optional live evidence is shown before any action or execution prompt.
    if [[ "${6:-}" == show-active ]]; then
        printf '\nNachweis der Ausgangslage durch das Administrationstool:\n'
        admin --no-label show-active
        printf '\nOhne aktivierte Policies enthält die Ausgabe keine aktivierten Policy-Einträge. Angezeigte Attribute sind davon unabhängig.\n'
    fi
    printf '\n%sAktion:%s\n  %s\n' "$color_section" "$color_reset" "$3"
    printf '\n%sErwartetes Verhalten:%s\n  %s\n' "$color_section" "$color_reset" "$4"
    printf '\n%sBeobachtung:%s\n  %s\n\n' "$color_section" "$color_reset" "$5"
    pause_demo
}
explain() { printf '\n→ %s\n' "$*"; }
step() {
    # Keep the last result visible until Enter, then present the next action.
    pause_demo 'Enter: zum nächsten Teilschritt | Strg+C: abbrechen '
    printf '\033[2J\033[H\n%s%s%s\n' "$color_heading" "$demo_current_chapter" "$color_reset"
    explain "$*"
    pause_demo
}
show_command() {
    local argument
    printf '\n%s$' "$color_command"
    # The worker runs in the repository. Relative paths are equivalent here and
    # keep the displayed commands short enough for the presentation pane.
    for argument in "$@"; do
        if [[ "$argument" == "$PROJECT_ROOT/"* ]]; then
            argument="./${argument#"$PROJECT_ROOT/"}"
        fi
        printf ' %q' "$argument"
    done
    printf '%s\n' "$color_reset"
}
show_output() {
    local status=0
    printf '%s' "$color_output"
    "$@" || status=$?
    printf '%s' "$color_reset"
    return "$status"
}
admin() {
    local quiet=0 label=1
    if [[ "${1:-}" == --quiet ]]; then quiet=1; shift; fi
    if [[ "${1:-}" == --no-label ]]; then label=0; shift; fi
    # The demo always uses the compact view, including internal polling.
    local command=("$ADM_TOOL_BIN" --policy-dir "$policy_dir" --attributes-dir "$attribute_dir" show-active)
    if (( quiet == 0 )); then
        # Show an equivalent repository-relative Bash command. Internal polling
        # stays quiet so it does not obscure the demo output.
        if (( label )); then printf '\n[Admin-Tool des Prototyps]\n'; fi
        show_command "${command[@]}"
    fi
    if (( quiet == 0 )); then
        show_output "${command[@]}"
    else
        "${command[@]}"
    fi
}
generations() {
    local output
    output="$(admin --quiet)" || return 1
    [[ "$output" =~ generation\ policy=([0-9]+).*attribute=([0-9]+) ]] || return 1
    printf '%s %s\n' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}"
}
wait_log() {
    local pattern="$1" offset="${2:-0}" deadline=$((SECONDS + DEMO_TIMEOUT_SECONDS))
    while (( SECONDS < deadline )); do
        alive || { fail 'Runtime wurde beendet; siehe Runtime-Log.'; return 1; }
        # Redirect to a file first: grep -q must not SIGPIPE tail under pipefail.
        tail -n "+$((offset + 1))" "$demo_root/runtime.log" > "$demo_root/log-slice"
        if grep -Fq -- "$pattern" "$demo_root/log-slice"; then return 0; fi
        sleep 0.1
    done
    fail "Timeout bei Logmeldung: $pattern"
}
wait_generation() {
    local kind="$1" before="$2" offset="$3" current deadline=$((SECONDS + DEMO_TIMEOUT_SECONDS))
    local policy attribute
    while (( SECONDS < deadline )); do
        alive || { fail 'Runtime wurde beendet.'; return 1; }
        if current="$(generations)"; then
            read -r policy attribute <<< "$current"
            if { [[ "$kind" == policy && "$policy" != "$before" ]]; } ||
               { [[ "$kind" == attribute && "$attribute" != "$before" ]]; }; then
                wait_log "scan completed policy_generation=$policy attribute_generation=$attribute" "$offset"
                observe "Aktiviert: Policygeneration $policy, Attributgeneration $attribute; FD-Prüfung abgeschlossen."
                return 0
            fi
        fi
        sleep 0.1
    done
    fail "Timeout beim Aktivieren von $kind."
}
publish() {
    local destination="$1"
    local publication=(bash ./scripts/publish-config.sh "./${demo_root#"$PROJECT_ROOT/"}/prepared" "./${destination#"$PROJECT_ROOT/"}")
    cat > "$demo_root/prepared"
    # Retain technical publication diagnostics without displaying internal commands.
    printf '%q ' "${publication[@]}" >> "$demo_root/publication.log"
    printf '\n' >> "$demo_root/publication.log"
    if ! "${publication[@]}" >> "$demo_root/publication.log" 2>&1; then
        fail "Veröffentlichung fehlgeschlagen; siehe $demo_root/publication.log."
        return 1
    fi
    if [[ "$destination" == "$policy_dir/"* ]]; then
        printf '\nFolgende Policy veröffentlicht (%s):\n' "${destination#"$PROJECT_ROOT/"}"
    else
        printf '\nFolgende Attribute veröffentlicht (%s):\n' "${destination#"$PROJECT_ROOT/"}"
    fi
    printf '%s' "$color_config"
    cat -- "$destination"
    printf '%s' "$color_reset"
}
show_policy_context() {
    local file
    for file in "$policy_dir"/*.policy; do
        [[ -f "$file" ]] || continue
        printf '\nUnveränderte Policy für die Zugriffsprüfung (%s):\n' "${file#"$PROJECT_ROOT/"}"
        printf '%s' "$color_config"
        cat -- "$file"
        printf '%s\n' "$color_reset"
    done
}
policy() {
    local name="$1" effect="$2" conditions="${3:-}" command="${4:-}" before offset
    before="$(generations)"
    offset="$(wc -l < "$demo_root/runtime.log")"
    {
        printf 'policy "%s"\n%s\n    action == "file_open";\n    resource.path == "%s";\n' "$name" "$effect" "$target"
        [[ -z "$command" ]] || printf '    command == "%s";\n' "$command"
        printf '%s\n' "$conditions"
    } | publish "$policy_dir/$name.policy"
    wait_generation policy "${before%% *}" "$offset"
}
attribute() {
    local relative="$1" text="$2" before offset
    before="$(generations)"
    offset="$(wc -l < "$demo_root/runtime.log")"
    printf '%s\n' "$text" | publish "$attribute_dir/$relative"
    wait_generation attribute "${before##* }" "$offset"
    show_policy_context
}
remove_policy() {
    local name="$1" before offset
    before="$(generations)"
    offset="$(wc -l < "$demo_root/runtime.log")"
    printf '\nDie Policy %s wird entfernt.\n' "$name"
    show_command rm -- "$policy_dir/$name.policy"
    rm -- "$policy_dir/$name.policy"
    wait_generation policy "${before%% *}" "$offset"
}
show_request() {
    local command="$1" uid="$2" file="$3" heading="${4:-Zugriffsanfrage vor der Dateiöffnung}"
    admin --quiet > "$demo_root/request.active"
    printf '\n%s%s%s\n' "$color_section" "$heading" "$color_reset"
    show_output python3 "$PROJECT_ROOT/scripts/demo/request.py" \
        "$demo_root/request.active" "$command" "$uid" "$file" "$PROJECT_ROOT"
}
show_decision() {
    local expected="$1" actual="$2" enforcement="$3" file="$4"
    local heading="${5:-Entscheidung zur Zugriffsanfrage}" expected_label actual_label
    case "$expected" in allow) expected_label=Permit ;; deny) expected_label=Deny ;; *) return 1 ;; esac
    case "$actual" in allow) actual_label=Permit ;; deny) actual_label=Deny ;; *) return 1 ;; esac
    if [[ "$file" == "$PROJECT_ROOT/"* ]]; then file="./${file#"$PROJECT_ROOT/"}"; fi
    printf '\n%s%s%s\n' "$color_section" "$heading" "$color_reset"
    printf '%s  Datei:          %s\n' "$color_output" "$file"
    printf '  Ergebnis:       %s\n' "$actual_label"
    printf '  Durchsetzung:   %s\n' "$enforcement"
    printf '  Erwartet:       %s%s\n' "$expected_label" "$color_reset"
    if [[ "$actual" == "$expected" ]]; then
        observe 'OK: Die beobachtete Durchsetzung entspricht der erwarteten Entscheidung.'
    else
        printf '%s  Prüfung:        Erwartete und beobachtete Entscheidung weichen ab.%s\n' "$color_error" "$color_reset"
        return 1
    fi
}
access_is() {
    local expected="$1" command="${2:-tails-demo}" uid="${3:--}" file="${4:-$target}" actual
    alive || { fail 'Runtime beendet.'; return 1; }
    show_request "$command" "$uid" "$file"
    local invocation=(python3 "$PROJECT_ROOT/scripts/demo/probe.py" access "$file" "$command" "$uid")
    actual="$("${invocation[@]}")"
    local enforcement='Die Datei wurde erfolgreich geöffnet und wieder geschlossen.'
    [[ "$actual" != deny ]] || enforcement='Die Dateiöffnung wurde mit EPERM verweigert.'
    show_decision "$expected" "$actual" "$enforcement" "$file" || {
        fail "Zugriff: erwartet $expected, beobachtet $actual ($command, UID $uid)."
        return 1
    }
}
command_access_is() {
    local expected="$1" command="$2" uid="$3" file="${4:-$target}" status=0 actual
    local output="$demo_root/command.stdout" error="$demo_root/command.stderr"
    alive || { fail 'Runtime beendet.'; return 1; }
    show_request "$command" "$uid" "$file"
    # Only the real UID changes. Effective UID 0 keeps ordinary DAC permissions
    # constant while the UID, command and resource policy filters are varied.
    local invocation=(setpriv --ruid "$uid" -- "$command" -- "$file")
    printf '\n[Dateizugriff durch das Programm %s]\n' "$command"
    show_command "${invocation[@]}"
    LC_ALL=C "${invocation[@]}" > "$output" 2> "$error" || status=$?
    if [[ -s "$output" ]]; then
        printf '%s[%s → stdout]\n' "$color_output" "$command"
        show_output cat -- "$output"
    fi
    if [[ -s "$error" ]]; then
        printf '%s[%s / Aufruf → stderr]\n' "$color_output" "$command"
        show_output cat -- "$error"
    fi
    if (( status == 0 )); then
        actual=allow
    elif (( status == 1 )) && grep -Eq "^${command}: " "$error" \
        && grep -Fq -- "$file" "$error" && grep -Fq 'Operation not permitted' "$error"; then
        actual=deny
    else
        fail "Aufruf von $command fehlgeschlagen (Exitstatus $status); kein nachgewiesener Policy-Deny."
        return 1
    fi
    local enforcement="Die Datei wurde durch $command gelesen (Exitstatus $status)."
    [[ "$actual" != deny ]] || enforcement="Die Dateiöffnung durch $command wurde mit EPERM verweigert (Exitstatus $status)."
    show_decision "$expected" "$actual" "$enforcement" "$file" || {
        fail "Zugriff durch $command: erwartet $expected, beobachtet $actual (Real-UID $uid)."
        return 1
    }
}
probe_state_is() {
    kill -0 "$probe_pid" 2>/dev/null || return 1
    python3 - "$probe_dir/state.json" "$1" <<'PY'
import json, sys
from pathlib import Path
path = Path(sys.argv[1])
if not path.exists():
    raise SystemExit(1)
state = json.loads(path.read_text())
expected = sys.argv[2] == 'open'
raise SystemExit(0 if state['protected'] == [expected] * 3 and state['controls'] == [True] * 2 else 1)
PY
}
start_probe() {
    probe_dir="$(mktemp -d "$demo_root/fd.XXXXXX")"
    explain 'Der FD-Beobachter öffnet die geschützte Datei dreimal und die Kontrolldatei zweimal. Die beiden Anfragekontexte lauten:'
    show_request tails-demo-fd 0 "$target"
    show_request tails-demo-fd 0 "$safe"
    printf '\n[FD-Beobachter: probe.py hold – Ausgabe im rechten unteren Bereich]\n'
    show_command python3 "$PROJECT_ROOT/scripts/demo/probe.py" hold "$target" "$safe" "$probe_dir"
    DEMO_OUTPUT_COLOR="$color_output" DEMO_COLOR_RESET="$color_reset" \
        python3 "$PROJECT_ROOT/scripts/demo/probe.py" hold "$target" "$safe" "$probe_dir" >> "$demo_root/observer.log" 2>&1 &
    probe_pid=$!
    local deadline=$((SECONDS + DEMO_TIMEOUT_SECONDS))
    while ! probe_state_is open; do
        kill -0 "$probe_pid" 2>/dev/null || { fail 'FD-Beobachter konnte Dateien nicht öffnen.'; return 1; }
        (( SECONDS < deadline )) || { fail 'Timeout beim Start des FD-Beobachters.'; return 1; }
        sleep 0.1
    done
}
stop_probe() {
    if [[ -n "$probe_pid" ]]; then
        kill -TERM "$probe_pid" 2>/dev/null || true
        wait "$probe_pid" 2>/dev/null || true
        probe_pid=''
    fi
}
expect_revoked() {
    local deadline=$((SECONDS + DEMO_TIMEOUT_SECONDS))
    while ! probe_state_is closed; do
        alive || { fail 'Runtime während des FD-Entzugs beendet.'; return 1; }
        kill -0 "$probe_pid" 2>/dev/null || { fail 'FD-Beobachter unerwartet beendet.'; return 1; }
        (( SECONDS < deadline )) || { fail 'FD-Entzug ausgeblieben oder Kontroll-FD geschlossen.'; return 1; }
        sleep 0.1
    done
    show_request tails-demo-fd 0 "$target" 'Anfragekontext nach Auswertung der geschützten FDs (keine neue Dateiöffnung)'
    show_decision deny deny 'Die drei geschützten Dateideskriptoren wurden geschlossen.' "$target" 'Entscheidung zu den bestehenden geschützten FDs'
    show_request tails-demo-fd 0 "$safe" 'Anfragekontext nach Auswertung der Kontroll-FDs (keine neue Dateiöffnung)'
    show_decision allow allow 'Die beiden Kontroll-Dateideskriptoren bleiben offen.' "$safe" 'Ergebnis für die bestehenden Kontroll-FDs'
    observe 'OK: Drei geschützte FDs entzogen, beide Kontroll-FDs offen, Hilfsprozess läuft weiter.'
}
assert_probe_identity() {
    python3 - "$probe_dir/ready.json" "$target" "$safe" <<'PY'
import json, os, sys
state = json.load(open(sys.argv[1]))
for key, path in [('protected', sys.argv[2]), ('controls', sys.argv[3])]:
    expected = os.stat(path)
    for fd in state[key]:
        actual = os.stat(f'/proc/{state["pid"]}/fd/{fd}')
        if (actual.st_dev, actual.st_ino) != (expected.st_dev, expected.st_ino):
            raise SystemExit('FD-Identität stimmt vor dem Auslöser nicht überein')
PY
}

setup_demo_bpffs() {
    local current_namespace mount_point="${1:-/sys/fs/bpf}"
    current_namespace="$(readlink /proc/self/ns/mnt)" || return 1
    if [[ -z "${DEMO_PARENT_MOUNT_NS:-}" || "$current_namespace" == "$DEMO_PARENT_MOUNT_NS" ]]; then
        fail 'Privater Mount-Namespace fehlt; kein Mount im ursprünglichen Namespace.'
        return 1
    fi
    [[ -d "$mount_point" ]] || { fail "Mountpunkt $mount_point fehlt."; return 1; }
    mount -t bpf -o mode=700 bpf "$mount_point" || {
        fail 'Eigenes Demo-bpffs konnte nicht eingehängt werden.'; return 1;
    }
    [[ "$(stat -f -c %T "$mount_point")" == bpf_fs ]] || { fail 'Demo-Mount ist kein bpffs.'; return 1; }
}

start_kernel_trace() {
    local setting original deadline
    mkdir "$demo_root/tracefs"
    mount -t tracefs tracefs "$demo_root/tracefs" || {
        fail 'tracefs konnte für die Kernel-Debugausgabe nicht eingehängt werden.'; return 1;
    }
    # The mount is private, but tracing switches and the consumed trace stream
    # are shared kernel state on this dedicated demo VM. Restore every switch.
    for setting in tracing_on options/trace_printk; do
        read -r original < "$demo_root/tracefs/$setting"
        trace_settings_paths+=("$demo_root/tracefs/$setting")
        trace_settings_values+=("$original")
        printf '1\n' > "$demo_root/tracefs/$setting"
    done
    printf '[Kernel-Debug] Reduzierter Deny-Modus: Nur endgültige Deny-Entscheidungen und Tail-Call-Fehler werden im Kernel protokolliert.\n' >> "$demo_root/runtime.log"
    DEMO_OUTPUT_COLOR="$color_output" DEMO_COLOR_RESET="$color_reset" \
        python3 "$PROJECT_ROOT/scripts/demo/kernel_trace.py" \
        "$demo_root/tracefs/trace_pipe" "$demo_root/kernel-ready" "$demo_root/kernel.log" \
        >> "$demo_root/runtime.log" 2>&1 &
    kernel_trace_pid=$!
    deadline=$((SECONDS + DEMO_TIMEOUT_SECONDS))
    while [[ ! -e "$demo_root/kernel-ready" ]]; do
        kill -0 "$kernel_trace_pid" 2>/dev/null || { fail 'Kernel-Trace-Leser konnte nicht gestartet werden; siehe Runtime-Log.'; return 1; }
        (( SECONDS < deadline )) || { fail 'Timeout beim Start des Kernel-Trace-Lesers.'; return 1; }
        sleep 0.1
    done
}

stop_kernel_trace() {
    local deadline index state status=0
    if [[ -n "$kernel_trace_pid" ]]; then
        kill -TERM "$kernel_trace_pid" 2>/dev/null || true
        deadline=$((SECONDS + 3))
        while (( SECONDS < deadline )); do
            state="$(ps -o stat= -p "$kernel_trace_pid")" || break
            [[ -n "$state" && "$state" != *Z* ]] || break
            sleep 0.1
        done
        kill -KILL "$kernel_trace_pid" 2>/dev/null || true
        wait "$kernel_trace_pid" 2>/dev/null || true
        kernel_trace_pid=''
    fi
    for index in "${!trace_settings_paths[@]}"; do
        printf '%s\n' "${trace_settings_values[$index]}" > "${trace_settings_paths[$index]}" || status=1
    done
    return "$status"
}

stop_runtime() {
    [[ -n "$runtime_pid" ]] || return 0
    kill -TERM "$runtime_pid" 2>/dev/null || true
    local deadline=$((SECONDS + 5))
    while alive && (( SECONDS < deadline )); do sleep 0.1; done
    if alive; then kill -KILL "$runtime_pid" 2>/dev/null || true; fi
    wait "$runtime_pid" 2>/dev/null || true
    runtime_pid=''
}

workspace_path() {
    case "$1" in
        files) printf '%s/demo/files\n' "$PROJECT_ROOT" ;;
        *) printf '%s/%s\n' "$PROJECT_ROOT" "$1" ;;
    esac
}

recover_demo_workspace() {
    local backup recovery name path
    # Called only after taking the demo/evaluation lock and rejecting a running
    # prototype. Validate the marker before using its path in privileged moves.
    backup="$(python3 - "$PROJECT_ROOT/demo/runs" "$workspace_marker" <<'PY'
from pathlib import Path
import sys
runs = Path(sys.argv[1]).resolve()
marker = Path(sys.argv[2])
try:
    reference = marker / 'backup-path'
    if marker.is_symlink() or not marker.is_dir() or reference.is_symlink() or not reference.is_file():
        raise ValueError('Sicherungsmarkierung ist unvollständig oder kein reguläres Verzeichnis')
    source = Path(reference.read_text().strip())
    backup = source.resolve(strict=True)
    if source.is_symlink() or not backup.is_dir() or backup.name != 'original' or backup.parent.parent != runs:
        raise ValueError('Sicherung liegt nicht im erwarteten Demo-Laufverzeichnis')
    print(backup)
except (OSError, ValueError) as error:
    print(f'Automatische Wiederherstellung nicht möglich: {error}. Markierung: {marker}', file=sys.stderr)
    raise SystemExit(1)
PY
)" || return 1
    for name in policies attributes files; do
        path="$(workspace_path "$name")"
        [[ ! -L "$path" && ( ! -e "$path" || -d "$path" ) && ! -L "$backup/$name" && ( ! -e "$backup/$name" || -d "$backup/$name" ) ]] || {
            fail "Wiederherstellung abgebrochen: kein reguläres Verzeichnis für $name. Alle verbleibenden Sicherungen bleiben erhalten."
            return 1
        }
    done
    [[ ! -L "$backup/directories.present" ]] || { fail 'Ungültiges Sicherungsmanifest.'; return 1; }
    recovery="$(mktemp -d "$demo_root/recovered.XXXXXX")"
    explain "Ein unterbrochener Demo-Lauf wird wiederhergestellt. Vorhandene Demo-Dateien werden unter ${recovery#"$PROJECT_ROOT/"} archiviert."
    for name in policies attributes files; do
        path="$(workspace_path "$name")"
        if [[ -d "$backup/$name" ]]; then
            if [[ -e "$path" ]]; then mv -- "$path" "$recovery/$name" || return 1; fi
            mv -- "$backup/$name" "$path" || return 1
        elif [[ -f "$backup/directories.present" ]] && ! grep -Fxq -- "$name" "$backup/directories.present"; then
            # This directory did not exist before that run. Preserve the demo
            # contents in the archive and restore its original absence.
            if [[ -e "$path" ]]; then mv -- "$path" "$recovery/$name" || return 1; fi
        fi
        # Without a manifest, a missing backup can also mean that this original
        # was already restored. Leave that directory unchanged rather than guess.
    done
    mv -- "$workspace_marker" "$recovery/previous-marker" || return 1
    explain 'Die vorhandenen Originalsicherungen wurden wiederhergestellt. Die Demo kann neu vorbereitet werden.'
}

prepare_demo_workspace() {
    local name path
    workspace_marker="$PROJECT_ROOT/demo/.workspace-active"
    if [[ -e "$workspace_marker" || -L "$workspace_marker" ]]; then
        recover_demo_workspace || return 1
    fi
    # Check every path before moving anything. The marker remains after an
    # incomplete restoration, preventing a later run from hiding the backups.
    for name in policies attributes files; do
        path="$(workspace_path "$name")"
        [[ ! -L "$path" && ( ! -e "$path" || -d "$path" ) ]] || {
            fail "Demo-Verzeichnis ist kein reguläres Verzeichnis: $path"; return 1;
        }
    done
    mkdir "$workspace_marker"
    owns_workspace=1
    printf '%s\n' "$demo_root/original" > "$workspace_marker/backup-path"
    mkdir "$demo_root/original"
    # Persist which directories existed before any moves. Recovery can then
    # distinguish an originally absent directory from an already-restored one.
    : > "$demo_root/original/directories.present"
    for name in policies attributes files; do
        path="$(workspace_path "$name")"
        if [[ -d "$path" ]]; then printf '%s\n' "$name" >> "$demo_root/original/directories.present"; fi
    done
    for name in policies attributes files; do
        path="$(workspace_path "$name")"
        if [[ -d "$path" ]]; then mv -- "$path" "$demo_root/original/$name"; fi
        workspace_dirs+=("$name")
        mkdir -p -- "$path"
    done
}

restore_demo_workspace() {
    local name path status=0
    [[ "$owns_workspace" == 1 ]] || return 0
    for name in "${workspace_dirs[@]-}"; do
        [[ -n "$name" ]] || continue
        path="$(workspace_path "$name")"
        if [[ -e "$path" ]]; then
            if ! mv -- "$path" "$demo_root/$name"; then status=1; continue; fi
        fi
        if [[ -d "$demo_root/original/$name" ]]; then
            mv -- "$demo_root/original/$name" "$path" || status=1
        fi
    done
    if (( status == 0 )); then
        rm -- "$workspace_marker/backup-path" || return 1
        rmdir -- "$workspace_marker" || return 1
        owns_workspace=0
    else
        printf 'Die Originalverzeichnisse konnten nicht vollständig wiederhergestellt werden. Sicherungen: %s/original\n' "$demo_root" >&2
    fi
    return "$status"
}

worker_cleanup() {
    local status=$? name
    trap - EXIT INT TERM HUP
    set +e
    stop_probe
    stop_runtime
    stop_kernel_trace || status=1
    if [[ "$owns_pins" == 1 ]]; then
        for name in POLICY_GENERATION ATTRIBUTE_GENERATION FILE_OPEN_STATIC_POLICIES FILE_OPEN_STREAM_POLICIES CURRENT_TIME ATTRIBUTES; do
            rm -f -- "$pin_dir/$name" || status=1
        done
    fi
    restore_demo_workspace || status=1
    printf '%s\n' "$status" > "$demo_root/exit-status"
    chown -R "$DEMO_CALLER_UID:$DEMO_CALLER_GID" "$demo_root"
    if (( status == 0 )); then
        printf '\nDie Demo wurde erfolgreich abgeschlossen. Die Logs bleiben erhalten.\n'
    else
        printf '\nDemo abgebrochen (Status %s). Diagnose: %s\n' "$status" "$demo_root"
    fi
    # Keep the result readable, including on an assertion failure. On HUP/TERM
    # there is no UI left to hold open.
    if [[ "$DEMO_AUTO" == 0 && "$status" -ne 130 && "$status" -ne 143 && -t 0 ]]; then
        read -r -p 'Enter: tmux-Demo schließen ' _ || true
    fi
    exit "$status"
}

demo_worker() {
    demo_root="$1"
    policy_dir="$PROJECT_ROOT/policies"
    attribute_dir="$PROJECT_ROOT/attributes"
    target="$PROJECT_ROOT/demo/files/protected.txt"
    safe="$PROJECT_ROOT/demo/files/control.txt"
    pin_dir=/sys/fs/bpf/tails-pdp
    runtime_pid='' probe_pid='' kernel_trace_pid='' owns_pins=0 demo_chapter_started=0
    trace_settings_paths=() trace_settings_values=()
    owns_workspace=0
    workspace_dirs=()
    exec > >(tee -a "$demo_root/transcript.log") 2>&1
    trap worker_cleanup EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM HUP

    [[ "$(uname -m)" == x86_64 ]] || { fail 'Der ptrace-basierte FD-Entzug benötigt x86_64-Linux.'; return 1; }
    [[ -r /sys/kernel/btf/vmlinux ]] || { fail 'Kernel-BTF fehlt.'; return 1; }
    [[ -r /sys/kernel/security/lsm ]] && grep -qw bpf /sys/kernel/security/lsm || {
        fail 'BPF-LSM ist nicht aktiv bzw. seine Konfiguration nicht lesbar.'; return 1;
    }
    mkdir -p /run/lock
    exec 9>/run/lock/tails-pdp-evaluation.lock
    flock -n 9 || { fail 'Eine Evaluation oder Demo läuft bereits.'; return 1; }
    if pgrep -x tails-pdp >/dev/null; then fail 'Es läuft bereits eine Instanz des Prototyps.'; return 1; fi
    (( $(printf '%s' "$target" | wc -c) <= 64 )) || {
        fail 'Der Repositorypfad ist zu lang: Der absolute Pfad von demo/files/protected.txt darf höchstens 64 Byte umfassen. Bitte einen kürzeren Checkout-Pfad verwenden.'; return 1;
    }
    setup_demo_bpffs
    owns_pins=1
    prepare_demo_workspace
    mkdir -p "$policy_dir" "$attribute_dir/subjects" "$attribute_dir/resources"
    printf 'Geschützter Demo-Inhalt\n' > "$target"
    printf 'Weiterhin zulässiger Kontroll-Inhalt\n' > "$safe"
    ln -- "$target" "$PROJECT_ROOT/demo/files/alias.txt"
    printf 'defcon = 5\n' > "$attribute_dir/system.attributes"
    cd "$PROJECT_ROOT"

    printf '\n%sPrototyp – geführte Live-Demo%s\n\n' "$color_heading" "$color_reset"
    printf 'Die Demo zeigt, wie Policies und Attribute die Zugriffsentscheidung verändern\n'
    printf 'und wie bereits geöffnete Dateideskriptoren entzogen werden.\n'

    printf '\n%sBedienung%s\n' "$color_section" "$color_reset"
    printf '  Enter führt durch die Kapitel und Teilschritte. Die Ergebnisse bleiben\n'
    printf '  bis zum Weitergehen sichtbar. Strg+C beendet die Demo.\n'

    printf '\n%sBildschirmaufteilung%s\n' "$color_section" "$color_reset"
    printf '  Links:         Erklärungen, Aktionen und Zugriffsprüfungen\n'
    printf '  Rechts oben:   Runtime-Log und Kernel-Debugausgaben\n'
    printf '  Rechts unten:  FD-Beobachter und Prüfergebnisse\n'

    printf '\n%sPrüfung der Zugriffe%s\n' "$color_section" "$color_reset"
    printf '  Die Zugriffshilfe probe.py access öffnet die jeweilige Datei mit os.open.\n'
    printf '  Für gezielte Prüfungen setzt sie den Kommandonamen und die Real-UID;\n'
    printf '  die effektive UID bleibt root. In Kapitel 2 laufen echtes cat und head.\n\n'
    printf '  Danach erscheint nur das Ergebnis: Dateiöffnung erlaubt oder verweigert.\n'
    printf '  Als Verweigerung gilt der Fehler EPERM. Andere Fehler brechen die Demo ab.\n'
    printf '  Vor dem Zugriff zeigt ein Anfrageblock die Aktion, das Kommando, den\n'
    printf '  Benutzer, die Datei und ihre Attribute aus dem aktivierten Stand.\n'
    printf '  Die Anzeige ist eine Momentaufnahme; sie zeichnet den Kernelaufruf nicht auf.\n'
    printf '  Danach zeigt ein Entscheidungsblock Permit oder Deny, die beobachtete\n'
    printf '  Durchsetzung und den Vergleich mit dem erwarteten Ergebnis. Ein Permit\n'
    printf '  bedeutet dabei nicht, dass eine bestimmte Permit-Policy zutreffen muss.\n'

    printf '\n%sAktive Konfiguration%s\n' "$color_section" "$color_reset"
    printf '  show-active zeigt die aktivierten Policies und Attributwerte.\n'
    printf '  Policygeneration und Attributgeneration kennzeichnen den jeweiligen\n'
    printf '  aktivierten Stand. Zusätzlich wird der tatsächliche Dateizugriff geprüft.\n'

    printf '\n%sDateien und Protokolle%s\n' "$color_section" "$color_reset"
    printf '  Policies: policies/   Attribute: attributes/   Dateien: demo/files/\n'
    printf '  Logs: %s\n\n' "$demo_root"
    pause_demo 'Enter: erstes Kapitel anzeigen | Strg+C: abbrechen '

    # Kapitel 1: Die Durchsetzung erst nach dem nachgewiesenen LSM-Attach prüfen.
    # Der leere Policy-Stand zeigt das Allow-Verhalten ohne passende Deny-Policy.
    chapter '1. Runtime starten und Ausgangszustand prüfen' \
        'Die Dateien sind vorbereitet:
  demo/files/protected.txt – die Datei, deren Zugriff durch Policies geschützt werden soll.
  demo/files/control.txt – eine separate Kontrolldatei, die weiterhin zugänglich bleiben soll.
  demo/files/alias.txt – ein Hardlink auf protected.txt; beide Pfade verweisen auf dieselbe Datei.

  Es läuft noch keine Runtime und es sind keine Policies geladen.' \
        'Der Prototyp wird gestartet. Dabei wird das eBPF-Programm geladen, die Maps werden vorbereitet und der file_open-Hook wird angehängt. Danach wird die geschützte Datei geöffnet.' \
        'Alle erwarteten Maps existieren, die Runtime läuft und die Dateiöffnung ist erlaubt: Ohne passende Deny-Policy wird kein Zugriff untersagt.' \
        'Rechts oben bestätigt die Runtime ihren Start. Deny-Entscheidungen des Kernelspace-PEP erscheinen dort als [Kernelspace-PEP] mit final=deny. USERSPACE_PEP ist die Logkennung des Userspace-PEP. Beide Durchsetzungspfade besitzen eine integrierte PDP-Funktion zur Policy-Auswertung. Links zeigt das Admin-Tool den geladenen Zustand; die anschließende OK-Zeile bestätigt den tatsächlichen Zugriff.'
    start_kernel_trace
    RUST_LOG=info TAILS_PDP_EBPF_DEBUG=deny TAILS_PDP_TIMING=0 "$TAILS_PDP_BIN" >> "$demo_root/runtime.log" 2>&1 &
    runtime_pid=$!
    wait_log 'Waiting for Ctrl-C'
    if ! grep -Fq 'Kernel debug logging mode=Deny' "$demo_root/runtime.log"; then
        fail 'Der reduzierte Kernel-Loggingmodus wurde nicht bestätigt. Bitte die Binaries mit ./scripts/demo.sh --build neu bauen.'
        return 1
    fi
    local name
    for name in POLICY_GENERATION ATTRIBUTE_GENERATION FILE_OPEN_STATIC_POLICIES FILE_OPEN_STREAM_POLICIES CURRENT_TIME ATTRIBUTES; do
        [[ -e "$pin_dir/$name" ]] || { fail "Map fehlt: $name"; return 1; }
    done
    wait_log 'scan completed'
    admin
    access_is allow
    explain 'Ergebnis: Die Runtime ist bereit und der Ausgangszugriff ist erlaubt. Ab jetzt bleibt derselbe Runtime-Prozess aktiv.'

    # Kapitel 2: Pro Negativkontrolle genau einen Filter verändern. Der Hardlink
    # belegt zusätzlich, dass die Ressourcenidentität und nicht der Pfad zählt.
    chapter '2. Statische Policies: Kommando, Benutzer und Ressource' \
        "Die Dateien sind zunächst zugänglich:
  Geschützte Datei: demo/files/protected.txt
  Kontrolldatei: demo/files/control.txt
  Hardlink auf die geschützte Datei: demo/files/alias.txt
  protected.txt und alias.txt bezeichnen dieselbe Datei; control.txt ist eine separate Datei." \
        'Eine Deny-Policy wird für genau drei gemeinsam erforderliche Merkmale veröffentlicht: Real-UID 60001, Kommando cat und die geschützte Ressource. Danach werden diese Merkmale einzeln variiert.' \
        'Nur die passende Kombination auf protected.txt wird verweigert. Eine andere UID, ein anderes Kommando und die separate control.txt bleiben erlaubt. alias.txt wird ebenfalls verweigert, weil Gerät und Inode mit protected.txt übereinstimmen.' \
        'Hier werden die Programme cat und head tatsächlich gestartet. setpriv setzt nur die Real-UID des jeweiligen Prozesses auf 60001 oder 60002; dafür sind keine zusätzlichen Benutzerkonten nötig. Die effektive UID bleibt root, damit gewöhnliche Dateirechte den Vergleich nicht beeinflussen. Der Kommando-Filter prüft den unter Linux geführten Kommandonamen comm: cat passt zur Policy, head nicht. Erlaubte Aufrufe zeigen den Dateiinhalt; beim verweigerten cat-Aufruf erscheint dessen echte Fehlermeldung.'
    explain 'Vor dem Laden der Policy kann cat mit Real-UID 60001 die geschützte Datei lesen.'
    command_access_is allow cat 60001
    step 'Die Deny-Policy für cat, Real-UID 60001 und die geschützte Datei wird veröffentlicht und anschließend geprüft.'
    policy scoped deny '    subject.uid == 60001;' cat
    explain 'Alle drei Filter passen: Die Dateiöffnung muss verweigert werden.'
    command_access_is deny cat 60001
    step 'Nur die Real-UID wird auf 60002 geändert. cat muss die geschützte Datei weiterhin lesen können.'
    command_access_is allow cat 60002
    step 'Nur das Kommando wird geändert: head muss die geschützte Datei mit Real-UID 60001 lesen können.'
    command_access_is allow head 60001
    step 'cat mit Real-UID 60001 liest jetzt die separate Kontrolldatei. Dieser Zugriff muss erlaubt bleiben.'
    command_access_is allow cat 60001 "$safe"
    step 'Der alternative Hardlink-Pfad bezeichnet dieselbe geschützte Datei. cat muss auch über diesen Pfad abgewiesen werden.'
    command_access_is deny cat 60001 "$PROJECT_ROOT/demo/files/alias.txt"
    admin show-active
    step 'Die Policy wird entfernt. Derselbe zuvor verweigerte Zugriff muss wieder möglich sein.'
    remove_policy scoped
    command_access_is allow cat 60001

    # Kapitel 3: Permit hebt ein gleichzeitig passendes Deny nicht auf.
    # Jede Veröffentlichung/Entfernung aktiviert einen neuen vollständigen Stand.
    chapter '3. Permit, Deny-Vorrang und Policy-Lebenszyklus' \
        'Nach dem Entfernen der vorherigen Policy sind keine Policies aktiviert. Dies wird vor den Änderungen mit show-active angezeigt. In diesem Schritt werden keine Benutzer- oder Kommandofilter verwendet.' \
        'Zuerst wird eine Permit-Policy geladen, dann eine passende Deny-Policy ergänzt und anschließend nur die Deny-Policy entfernt. Zum Schluss wird auch die Permit-Policy entfernt.' \
        'Die Zugriffe folgen der Reihenfolge erlaubt → verweigert → erlaubt. Bei gleichzeitig passenden Policies hat Deny Vorrang vor Permit.' \
        'Die Policygeneration ändert sich bei den Veröffentlichungen und Entfernungen. Neue Entscheidungen werden ohne Neustart wirksam. Die Reihenfolge der Dateinamen bestimmt keine Priorität.' show-active
    explain 'Zuerst wird eine Permit-Policy geladen. Der Zugriff ist damit erlaubt.'
    policy permit permit
    access_is allow
    step 'Eine passende Deny-Policy wird ergänzt. Bei gleichzeitig passenden Permit- und Deny-Policies hat Deny Vorrang.'
    policy deny deny
    access_is deny
    admin
    step 'Nur die Deny-Policy wird entfernt; die Permit-Policy bleibt geladen. Der Zugriff ist danach wieder erlaubt.'
    remove_policy deny
    access_is allow
    step 'Die Permit-Policy wird zum Abschluss dieses Kapitels entfernt.'
    remove_policy permit

    # Kapitel 4: Bei unveränderter Policy die Entscheidung allein über einen
    # Systemattributwert ändern; Attribut- und Policygeneration sind getrennt.
    chapter '4. Dynamisches Systemattribut' \
        'Das globale Attribut system.defcon steht auf 5. Diese Zahl dient als dynamischer Kontext der Zugriffsentscheidung.' \
        'Eine Deny-Policy mit system.defcon <= 2 wird geladen. Anschließend wird nur der Attributwert von 5 auf 2 und zurück auf 5 geändert.' \
        'Bei 5 ist die Deny-Bedingung falsch und der Zugriff erlaubt. Bei 2 ist sie erfüllt und der Zugriff verweigert. Nach der Rückkehr zu 5 ist er wieder erlaubt.' \
        'Die Policydatei bleibt während der Attributwechsel gleich. Im Log und im Admin-Tool ändert sich der Attributstand; die Runtime muss dafür nicht neu gestartet werden.'
    policy context deny '    system.defcon <= 2;'
    access_is allow
    step 'DEFCON sinkt auf 2: Die bereits geladene Deny-Policy trifft jetzt zu.'
    attribute system.attributes 'defcon = 2'
    access_is deny
    admin show-active
    step 'DEFCON steigt wieder auf 5: Dieselbe Policy trifft nicht mehr zu.'
    attribute system.attributes 'defcon = 5'
    access_is allow
    step 'Die Demo-Policy dieses Kapitels wird entfernt.'
    remove_policy context

    # Kapitel 5: System-, Subjekt- und Ressourcenattribute sind konjunktiv.
    # Fehlende oder anders typisierte Werte erfüllen den Stringvergleich nicht;
    # das ist hier ein gültiger Attributstand, kein abgelehntes Update wie in 6.
    chapter '5. Subject-/Resource-Attribute und UND-Verknüpfung' \
        'Attribute können für das gesamte System, für einen Benutzer und für eine konkrete Datei hinterlegt werden. Der normale Demo-Zugriff läuft mit Real-UID 0.' \
        'DEFCON wird auf 2, die Rolle von UID 0 auf engineer und die Dateiklassifikation auf internal gesetzt. Eine Deny-Policy verknüpft alle drei Bedingungen mit UND. Danach werden einzelne Werte geändert.' \
        'Deny gilt nur, wenn alle drei Bedingungen erfüllt sind. Rolle intern oder Klassifikation public reichen jeweils aus, damit diese Deny-Policy nicht mehr passt.' \
        'Anschließend wird das Attribut position zunächst weggelassen und danach auf die Zahl 1 statt auf die Zeichenkette "engineer" gesetzt. Beide Attributstände sind gültig, erfüllen aber den Vergleich mit "engineer" nicht. Deshalb greift hier kein Deny.'
    attribute system.attributes 'defcon = 2'
    attribute subjects/0.attributes 'position = "engineer"'
    attribute "resources${target}.attributes" 'classification = "internal"'
    policy combined deny $'    system.defcon <= 2;\n    subject.position == "engineer";\n    resource.classification == "internal";'
    access_is deny
    step 'Nur die Rolle wird von engineer auf intern geändert. Damit ist eine der drei UND-Bedingungen falsch.'
    attribute subjects/0.attributes 'position = "intern"'
    access_is allow
    step 'Die Rolle wird auf engineer zurückgesetzt. Damit sind wieder alle drei Bedingungen erfüllt.'
    attribute subjects/0.attributes 'position = "engineer"'
    access_is deny
    step 'Jetzt wird nur die Dateiklassifikation von internal auf public geändert. Damit passt die Deny-Policy nicht mehr.'
    attribute "resources${target}.attributes" 'classification = "public"'
    access_is allow
    step 'Mit classification=internal sind wieder alle drei Bedingungen erfüllt.'
    attribute "resources${target}.attributes" 'classification = "internal"'
    access_is deny
    step 'Jetzt fehlt position vollständig. Die Veröffentlichung ist gültig, der Rollenvergleich ergibt aber keinen Treffer.'
    attribute subjects/0.attributes '# position fehlt'
    access_is allow
    step 'position wird auf die Zahl 1 statt auf eine Zeichenkette gesetzt. Die Zahl 1 stimmt nicht mit der Zeichenkette "engineer" überein.'
    attribute subjects/0.attributes 'position = 1'
    access_is allow
    step 'position wird wieder auf die Zeichenkette "engineer" gesetzt: Alle Bedingungen passen und der Zugriff wird verweigert.'
    attribute subjects/0.attributes 'position = "engineer"'
    access_is deny
    admin
    step 'Die Demo-Policy dieses Kapitels wird entfernt.'
    remove_policy combined

    # Kapitel 6: Syntax-/Validierungsfehler dürfen keine neue Generation
    # aktivieren. Nach der Ablehnung muss eine gültige Korrektur weiter möglich sein.
    chapter '6. Ungültige Updates und anschließende Korrektur' \
        'DEFCON steht noch auf 2. Eine passende Deny-Policy wird geladen. Vor jedem fehlerhaften Update werden beide Generationsnummern gespeichert.' \
        'Zuerst wird eine Policy mit fehlendem Semikolon veröffentlicht. Nach ihrer Korrektur wird DEFCON=9 veröffentlicht, obwohl für dieses Attribut nur 1 bis 5 zulässig sind.' \
        'Beide fehlerhaften Updates werden verworfen. Die zuletzt gültigen Generationen und das wirksame Deny bleiben erhalten. Gültige Korrekturen werden anschließend wieder übernommen.' \
        'Rechts oben erscheint die Ablehnung. Links zeigt show-active die aktivierten Policies, Attribute und Generationen vor und nach jedem ungültigen Update sowie nach den gültigen Korrekturen. Ungültige Updates ändern keine Generation; erst die gültigen Korrekturen aktivieren einen neuen Stand. Der tatsächliche Zugriff wird zusätzlich geprüft.'
    policy robust deny '    system.defcon <= 2;'
    local before offset
    explain 'Aktiver Ausgangszustand vor der ungültigen Policy: Die Deny-Policy robust ist aktiviert und DEFCON steht auf 2.'
    admin show-active
    before="$(generations)"
    offset="$(wc -l < "$demo_root/runtime.log")"
    step 'Die nächste Policy ist absichtlich syntaktisch fehlerhaft. Sie darf nicht aktiviert werden.'
    printf 'policy "broken"\ndeny\n action == "file_open"\n' | publish "$policy_dir/broken.policy"
    wait_log 'POLICY sync failed' "$offset"
    [[ "$(generations)" == "$before" ]] || { fail 'Ungültige Policy änderte die Generation.'; return 1; }
    explain 'Aktiver Zustand nach der Ablehnung: broken wurde nicht aktiviert. Policies, Attribute und beide Generationen bleiben unverändert.'
    admin show-active
    observe "Ungültige Policy verworfen: Policygeneration ${before%% *} und Attributgeneration ${before##* } unverändert."
    access_is deny
    step 'Die fehlerhafte Datei wird durch eine gültige Permit-Policy ersetzt. Die bereits aktivierte Deny-Policy hat weiterhin Vorrang.'
    policy broken permit
    explain 'Nach der gültigen Policy-Korrektur ist broken zusätzlich aktiviert. Die Deny-Policy robust gilt weiterhin.'
    admin show-active
    access_is deny
    step 'Die korrigierte Policy broken wird entfernt. Danach wird der aktive Ausgangszustand für die Attributprüfung angezeigt.'
    remove_policy broken
    explain 'Aktiver Ausgangszustand vor dem ungültigen Attribut: broken wurde wieder entfernt. Die Deny-Policy robust und DEFCON=2 bleiben aktiv.'
    admin show-active
    before="$(generations)"
    offset="$(wc -l < "$demo_root/runtime.log")"
    step 'DEFCON=9 ist unzulässig. Der aktive Wert muss trotz geänderter Quelldatei bei 2 bleiben.'
    printf 'defcon = 9\n' | publish "$attribute_dir/system.attributes"
    wait_log 'Ignoring invalid stream attributes' "$offset"
    [[ "$(generations)" == "$before" ]] || { fail 'Ungültiges Attribut änderte die Generation.'; return 1; }
    explain 'Aktiver Zustand nach der Ablehnung von DEFCON=9: show-active zeigt weiterhin DEFCON=2 sowie dieselben Policies und Generationen.'
    admin show-active
    observe "Ungültiges Attribut verworfen: Policygeneration ${before%% *} und Attributgeneration ${before##* } unverändert."
    access_is deny
    step 'Mit dem gültigen Wert 5 wird ein neuer Attributstand aktiviert. Die Deny-Bedingung ist danach falsch und der Zugriff wieder erlaubt.'
    attribute system.attributes 'defcon = 5'
    explain 'Aktiver Zustand nach der gültigen Attribut-Korrektur: DEFCON=5 und die neue Attributgeneration sind sichtbar. Die Deny-Policy robust ist weiterhin aktiviert, ihre Bedingung ist jetzt jedoch falsch.'
    admin show-active
    access_is allow
    step 'Die Demo-Policy dieses Kapitels wird entfernt.'
    remove_policy robust

    # Kapitel 7: file_open schützt neue Öffnungen. Der Userspace-PEP muss
    # zusätzlich bestehende FDs selektiv entziehen, ohne den Prozess zu beenden.
    chapter '7. Bereits geöffnete FDs durch eine neue Policy entziehen' \
        'Bisher wurden neue Dateiöffnungen geprüft. Ein Prozess kann eine Datei aber schon geöffnet haben, bevor eine neue Policy veröffentlicht wird.' \
        'Ein Beobachter mit drei offenen FDs zur geschützten Datei und zwei offenen FDs zur Kontrolldatei wird gestartet. Erst im nächsten Schritt wird eine passende Deny-Policy veröffentlicht.' \
        'Zunächst müssen alle fünf FDs offen sein. Nach der Policyaktivierung prüft der Userspace-PEP bestehende FDs erneut und entzieht ausschließlich die drei geschützten.' \
        'FD bedeutet Dateideskriptor: eine offene Dateireferenz in einem Prozess. Rechts unten zeigt True einen offenen FD und False einen geschlossenen. Der Beobachterprozess soll weiterlaufen.'
    start_probe
    chapter '7a. FDs sind offen – jetzt Deny veröffentlichen' \
        'Der Beobachter hält alle fünf FDs offen. Vor der Änderung wird zusätzlich geprüft, dass diese FDs noch auf die erwarteten Dateien verweisen.' \
        'Mit Enter wird eine Deny-Policy für die geschützte Datei und das Kommando tails-demo-fd veröffentlicht. Die Policyaktivierung löst eine erneute FD-Prüfung aus.' \
        'Die drei geschützten FDs wechseln auf False. Beide Kontroll-FDs bleiben True; der Prozess wird nicht beendet.' \
        'Rechts oben ist die Policyaktivierung mit anschließendem Scan sichtbar. Rechts unten ist der tatsächliche FD-Zustand zu sehen. Ein Logeintrag allein genügt nicht als Nachweis.'
    assert_probe_identity
    policy revoke deny '' tails-demo-fd
    expect_revoked
    step 'Der selektive Entzug ist bestätigt. Der Beobachter wird jetzt gezielt beendet und die Demo-Policy für das nächste Kapitel entfernt.'
    stop_probe
    remove_policy revoke

    # Kapitel 8: Deny ist bereits geladen, seine Bedingung aber zunächst falsch.
    # Nur die Attributgeneration darf sich durch den Auslöser ändern.
    chapter '8. FD-Entzug ausschließlich durch Attributänderung' \
        'DEFCON steht auf 5. Vor dem Öffnen wird eine Deny-Policy mit system.defcon <= 2 installiert. Die Policy ist aktiviert, ihre Bedingung ist jedoch noch nicht erfüllt.' \
        'Ein neuer Beobachter öffnet drei geschützte und zwei Kontroll-FDs. Danach wird im nächsten Schritt ausschließlich das Systemattribut geändert.' \
        'Solange DEFCON=5 gilt, bleiben alle FDs offen. Der spätere Wechsel auf 2 muss den Entzug ohne Änderung der Policydatei auslösen.' \
        'Eine geladene Policy und eine erfüllte Bedingung sind zu unterscheiden. enabled im Admin-Tool bedeutet, dass die Policy aktiviert ist; ihre Bedingungen werden für den jeweiligen Zugriff ausgewertet.'
    policy revoke deny '    system.defcon <= 2;' tails-demo-fd
    start_probe
    chapter '8a. Nur das Systemattribut ändern' \
        'Die Policy ist bereits geladen und der Beobachter hält seine FDs offen. Die aktuelle Policygeneration wird gespeichert.' \
        'Mit Enter wird ausschließlich DEFCON=2 veröffentlicht. Der Attributloader aktiviert den neuen Wert und löst damit eine FD-Prüfung aus.' \
        'Die Attributgeneration steigt, die Policygeneration bleibt gleich. Nur die drei geschützten FDs werden geschlossen; beide Kontroll-FDs bleiben offen.' \
        'Rechts oben wird ein Scan mit Ursache attributes:<Generation> erwartet. Damit wird der Attributwechsel als Auslöser nachgewiesen. Die Policy bleibt dabei unverändert.'
    assert_probe_identity
    before="$(generations)"
    offset="$(wc -l < "$demo_root/runtime.log")"
    attribute system.attributes 'defcon = 2'
    local current
    current="$(generations)"
    [[ "${before%% *}" == "${current%% *}" ]] || { fail 'Policygeneration unerwartet geändert.'; return 1; }
    wait_log "scan started cause=[attributes:${current##* }]" "$offset"
    expect_revoked
    step 'Der FD-Entzug durch die Attributänderung ist bestätigt. Beobachter und Demo-Policy werden für das nächste Kapitel zurückgesetzt.'
    stop_probe
    remove_policy revoke

    # Kapitel 9: Erst nach der Enter-Pause die Grenze berechnen. Ab dem Öffnen
    # nichts mehr veröffentlichen; Zeit-Trigger und konstante Generationen prüfen.
    chapter '9. FD-Entzug ausschließlich durch eine Zeitgrenze' \
        'Eine Zeitbedingung kann ihren Wahrheitswert ändern, ohne dass jemand eine Policy oder ein Attribut veröffentlicht.' \
        'Nach dem Drücken der Enter-Taste wird eine Grenze zwölf Sekunden in der Zukunft berechnet. Die zeitabhängige Policy wird geladen und die Dateien werden vor dieser Grenze geöffnet. Anschließend wird ohne weitere Konfigurationsänderung gewartet.' \
        'Vor der Grenze sind die FDs offen. Nach Erreichen der Grenze wird die Deny-Bedingung wahr und ein zeitgetriggerter Scan entzieht die drei geschützten FDs. Beide Konfigurationsgenerationen bleiben gleich.' \
        'Die Uhr wird nicht verstellt. Der große Modulus 4294967296 macht den Vergleich in der aktuellen Unix-Epoche zu einem einmaligen nahen Übergang. Im Log ist time:<Zeitgrenze> der Auslöser. Während dieser zwölf Sekunden gibt es keine weitere Enter-Pause.'
    local boundary
    boundary=$(( $(date +%s) + 12 ))
    (( boundary < 4294967296 )) || { fail 'Zeitgrenze außerhalb des Demo-Modulus.'; return 1; }
    policy timed deny "    environment.time % 4294967296 >= $boundary;" tails-demo-fd
    start_probe
    assert_probe_identity
    (( $(date +%s) < boundary - 2 )) || { fail 'Einrichtung zu langsam: Zeitgrenze schon zu nah.'; return 1; }
    access_is allow tails-demo-fd
    before="$(generations)"
    offset="$(wc -l < "$demo_root/runtime.log")"
    observe "Es wird auf den Unix-Zeitpunkt $boundary gewartet. Es erfolgen weder eine Veröffentlichung noch ein Neustart."
    wait_log "scan started cause=[time:$boundary]" "$offset"
    wait_log "scan completed policy_generation=${before%% *} attribute_generation=${before##* }" "$offset"
    expect_revoked
    [[ "$(generations)" == "$before" ]] || { fail 'Konfigurationsgeneration an Zeitgrenze verändert.'; return 1; }
    python3 - "$probe_dir/state.json" "$boundary" <<'PY'
import json, sys
state = json.load(open(sys.argv[1]))
if state['unix_ns'] < int(sys.argv[2]) * 1_000_000_000:
    raise SystemExit('FDs vor der Zeitgrenze geschlossen')
PY
    access_is deny tails-demo-fd
    step 'Der Zeitauslöser, die unveränderten Generationen und der FD-Entzug sind bestätigt. Der Beobachter wird beendet und die Policy entfernt; danach muss eine neue Dateiöffnung wieder erlaubt sein.'
    stop_probe
    remove_policy timed
    access_is allow tails-demo-fd

    # Kapitel 10: UTC-Felder ergänzen die Modulo-Demo. Immer wahre Vergleiche
    # vermeiden eine Abhängigkeit von der Vorführungszeit und zeigen Deny-Vorrang.
    chapter '10. UTC-Zeitbedingung und abschließende Inspektion' \
        'Neben Unix-Zeit mit Modulus unterstützt der Prototyp UTC-Zeitfelder.' \
        'Zuerst wird eine Permit-Policy mit environment.utc.minute >= 0 geladen und der Zugriff geprüft. Danach kommt eine Deny-Policy mit environment.utc.hour >= 0 hinzu. Abschließend werden die aktivierten Policies und Attribute angezeigt.' \
        'Beide Bedingungen sind zu jeder gültigen Tageszeit wahr. Mit der Permit-Policy ist der Zugriff erlaubt. Bei gleichzeitig passenden Permit- und Deny-Policies hat Deny Vorrang und der Zugriff wird verweigert.' \
        'Die bewusst immer wahren Vergleiche zeigen die UTC-Felder unabhängig von der Uhrzeit der Vorführung. Das Admin-Tool zeigt die Policies, die Zugriffshilfe prüft deren tatsächliche Wirkung.'
    policy stream-permit permit '    environment.utc.minute >= 0;'
    access_is allow
    step 'Die zusätzliche UTC-Deny-Policy wird veröffentlicht. Sie hat Vorrang vor der passenden Permit-Policy.'
    policy utc deny '    environment.utc.hour >= 0;'
    explain 'Die zusätzliche UTC-Deny-Policy hat Vorrang vor der passenden Permit-Policy.'
    access_is deny
    admin
    observe 'Alle Demo-Kapitel erfolgreich geprüft.'
}

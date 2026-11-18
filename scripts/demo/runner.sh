#!/usr/bin/env bash
# Sourced by demo.sh --isolated-worker. demo_worker sets up the environment
# and runs the individual scenarios in cases/.

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
    for argument in "$@"; do
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
        # Internal polling stays quiet so it does not obscure the demo output.
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
        printf '\nFolgende Policy veröffentlicht (%s):\n' "$destination"
    else
        printf '\nFolgende Attribute veröffentlicht (%s):\n' "$destination"
    fi
    printf '%s' "$color_config"
    cat -- "$destination"
    printf '%s' "$color_reset"
}
show_policy_context() {
    local file
    for file in "$policy_dir"/*.policy; do
        [[ -f "$file" ]] || continue
        printf '\nUnveränderte Policy für die Zugriffsprüfung (%s):\n' "$file"
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
        "$demo_root/request.active" "$command" "$uid" "$file"
}
show_decision() {
    local expected="$1" actual="$2" enforcement="$3" file="$4"
    local heading="${5:-Entscheidung zur Zugriffsanfrage}" expected_label actual_label
    case "$expected" in allow) expected_label=Permit ;; deny) expected_label=Deny ;; *) return 1 ;; esac
    case "$actual" in allow) actual_label=Permit ;; deny) actual_label=Deny ;; *) return 1 ;; esac
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
    explain "Ein unterbrochener Demo-Lauf wird wiederhergestellt. Vorhandene Demo-Dateien werden unter $recovery archiviert."
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
        fail "Der Repositorypfad ist zu lang: $target darf höchstens 64 Byte umfassen. Bitte einen kürzeren Checkout-Pfad verwenden."; return 1;
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
    printf 'Die Demo zeigt, wie Policies, Attribute und Zeitbedingungen den\n'
    printf 'Dateizugriff steuern und bereits geöffnete Dateideskriptoren entzogen werden.\n'

    printf '\n%sBedienung%s\n' "$color_section" "$color_reset"
    printf '  Enter führt zum nächsten Schritt. Strg+C beendet die Demo.\n'

    printf '\n%sAnzeige%s\n' "$color_section" "$color_reset"
    printf '  Links:         Erklärungen, Zugriffsanfragen und Entscheidungen\n'
    printf '  Rechts oben:   Runtime- und Kernel-Logs\n'
    printf '  Rechts unten:  Zustand der offenen Dateideskriptoren\n'

    printf '\n%sDateien und Protokolle%s\n' "$color_section" "$color_reset"
    printf '  Policies:  %s\n  Attribute: %s\n  Dateien:   %s\n' "$policy_dir" "$attribute_dir" "${target%/*}"
    printf '  Logs: %s\n\n' "$demo_root"
    pause_demo 'Enter: erstes Kapitel anzeigen | Strg+C: abbrechen '

    # Die Fälle verwenden denselben Demo-Zustand und bauen aufeinander auf.
    source "$PROJECT_ROOT/scripts/demo/cases/01-runtime-start.sh"
    source "$PROJECT_ROOT/scripts/demo/cases/02-statische-policies.sh"
    source "$PROJECT_ROOT/scripts/demo/cases/03-policy-lebenszyklus.sh"
    source "$PROJECT_ROOT/scripts/demo/cases/04-systemattribut.sh"
    source "$PROJECT_ROOT/scripts/demo/cases/05-subjekt-und-ressourcenattribute.sh"
    source "$PROJECT_ROOT/scripts/demo/cases/06-ungueltige-updates.sh"
    source "$PROJECT_ROOT/scripts/demo/cases/07-fd-entzug-policy.sh"
    source "$PROJECT_ROOT/scripts/demo/cases/08-fd-entzug-attribut.sh"
    source "$PROJECT_ROOT/scripts/demo/cases/09-fd-entzug-zeitgrenze.sh"
    source "$PROJECT_ROOT/scripts/demo/cases/10-utc-zeitbedingungen.sh"

    observe 'Alle Demo-Kapitel erfolgreich geprüft.'
}

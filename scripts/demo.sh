#!/usr/bin/env bash
# Guided live demo. Runtime and configuration changes run only in the worker.
set -Eeuo pipefail

PROJECT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
export PROJECT_ROOT

usage() {
    cat <<'EOF'
Aufruf: ./scripts/demo.sh [--auto] [--build]

  Ohne Optionen: geführte tmux-Demo, Enter führt den nächsten Schritt aus.
  --auto         Schritte ohne Enter-Pausen ausführen.
  --build        Release-Binaries vor der Demo neu bauen.
  --help         Diese Hilfe anzeigen.

Benötigt ein dediziertes x86_64-Linux-System mit BPF-LSM und BTF.
Fehlende Programme werden über scripts/demo/shell.nix offline bereitgestellt.
Alle Nix-Pakete und Buildwerkzeuge müssen bereits lokal vorhanden sein.
Nix selbst muss dafür bereits installiert sein. sudo kann ein Passwort anfordern.
TAILS_PDP_BIN und ADM_TOOL_BIN können vorhandene Binaries auswählen.
DEMO_TIMEOUT_SECONDS (Standard 30) begrenzt technische Wartephasen.
EOF
}

if [[ "${1:-}" == --worker ]]; then
    shift
    [[ $# -eq 1 && $EUID -eq 0 ]] || exit 2
    # Keep the wrapper outside the namespace so unshare failures remain visible
    # in tmux even when the actual worker could not start its cleanup trap.
    original_mount_ns="$(readlink /proc/self/ns/mnt)"
    if DEMO_PARENT_MOUNT_NS="$original_mount_ns" unshare --mount --propagation private -- \
        bash "$PROJECT_ROOT/scripts/demo.sh" --isolated-worker "$1"; then
        exit 0
    else
        status=$?
        if [[ ! -e "$1/exit-status" ]]; then
            printf '%s\n' "$status" > "$1/exit-status"
            printf '\nPrivater Mount-Namespace konnte nicht gestartet werden (Status %s).\n' "$status" >&2
            if [[ "${DEMO_AUTO:-0}" == 0 && -t 0 ]]; then read -r -p 'Enter: Demo schließen ' _ || true; fi
        fi
        exit "$status"
    fi
fi

if [[ "${1:-}" == --isolated-worker ]]; then
    shift
    [[ $# -eq 1 && $EUID -eq 0 ]] || exit 2
    # This branch is called by the launcher with an explicit environment.
    # The documented demo chapters and their audience-facing explanations live
    # in demo_worker() in scripts/demo/runner.sh.
    source "$PROJECT_ROOT/scripts/demo/runner.sh"
    demo_worker "$1"
    exit
fi

DEMO_AUTO=0
build=0
for argument in "$@"; do
    case "$argument" in
        --help|-h) usage; exit 0 ;;
        --auto) DEMO_AUTO=1 ;;
        --build) build=1 ;;
        *) printf 'Unbekannte Option: %s\n' "$argument" >&2; usage >&2; exit 2 ;;
    esac
done
[[ "$(uname -s)" == Linux ]] || { echo 'Die Live-Demo benötigt Linux.' >&2; exit 1; }
[[ -t 0 && -t 1 ]] || { echo 'Bitte die Demo in einem interaktiven Terminal starten.' >&2; exit 1; }

# Resolve the host's privilege wrapper before Nix changes PATH, and preserve the
# absolute path for the Nix re-exec, authentication and the tmux worker alike.
if (( EUID != 0 )); then
    source "$PROJECT_ROOT/scripts/demo/dependencies.sh"
    DEMO_SUDO_BIN="$(resolve_demo_sudo)"
    export DEMO_SUDO_BIN
fi

missing=()
for program in bash cat chmod chown date dirname env flock grep id mkdir mkfifo mktemp mount mv pgrep ps python3 readlink rm rmdir sleep stat tail tee tmux uname unshare wc ln; do
    command -v "$program" >/dev/null 2>&1 || missing+=("$program")
done
if (( ${#missing[@]} )); then
    printf 'Fehlende Werkzeuge: %s\n' "${missing[*]}"
    if [[ "${TAILS_DEMO_NIX:-0}" == 1 ]]; then
        echo 'Die Demo-Nix-Shell stellt nicht alle benötigten Programme bereit.' >&2
        exit 1
    fi
    command -v nix-shell >/dev/null 2>&1 || {
        echo 'nix-shell fehlt. Bitte Nix auf dem Zielsystem einrichten und erneut starten.' >&2
        exit 1
    }
    # %q quotes each original argument as Bash code; no eval of user text.
    printf -v invocation '%q ' bash "$PROJECT_ROOT/scripts/demo.sh" "$@"
    export TAILS_DEMO_NIX=1
    exec nix-shell --option substitute false --option builders '' -j 0 "$PROJECT_ROOT/scripts/demo/shell.nix" --run "$invocation"
fi

TAILS_PDP_BIN="${TAILS_PDP_BIN:-$PROJECT_ROOT/target/release/tails-pdp}"
ADM_TOOL_BIN="${ADM_TOOL_BIN:-$PROJECT_ROOT/target/release/tails-pdp-admintool}"
# Resolve overrides before the worker changes its working directory.
TAILS_PDP_BIN="$(python3 -c 'import os,sys; print(os.path.abspath(sys.argv[1]))' "$TAILS_PDP_BIN")"
ADM_TOOL_BIN="$(python3 -c 'import os,sys; print(os.path.abspath(sys.argv[1]))' "$ADM_TOOL_BIN")"
if (( build )) || [[ ! -x "$TAILS_PDP_BIN" || ! -x "$ADM_TOOL_BIN" ]]; then
    command -v nix-shell >/dev/null 2>&1 || {
        echo 'Zum Bauen fehlt nix-shell; alternativ fertige Binaries über TAILS_PDP_BIN und ADM_TOOL_BIN auswählen.' >&2
        exit 1
    }
    echo 'Baue den Prototyp ausschließlich aus lokalen Quellen …'
    printf -v build_command 'bash %q' "$PROJECT_ROOT/scripts/demo/build.sh"
    nix-shell --option substitute false --option builders '' -j 0 "$PROJECT_ROOT/nix-config/shell.nix" --run "$build_command"
fi
[[ -x "$TAILS_PDP_BIN" && -x "$ADM_TOOL_BIN" ]] || { echo 'Ausgewählte Binaries fehlen.' >&2; exit 1; }
DEMO_TIMEOUT_SECONDS="${DEMO_TIMEOUT_SECONDS:-30}"
[[ "$DEMO_TIMEOUT_SECONDS" =~ ^[1-9][0-9]*$ ]] || { echo 'DEMO_TIMEOUT_SECONDS muss eine positive Ganzzahl sein.' >&2; exit 2; }

# Authenticate in the worker's tmux terminal: sudo timestamps are normally per tty.
demo_caller_uid="$(id -u)"
demo_caller_gid="$(id -g)"
if (( EUID == 0 )) && [[ -n "${SUDO_UID:-}" && -n "${SUDO_GID:-}" ]]; then
    demo_caller_uid="$SUDO_UID"
    demo_caller_gid="$SUDO_GID"
fi
for generated_directory in "$PROJECT_ROOT/demo" "$PROJECT_ROOT/demo/runs"; do
    if [[ ! -d "$generated_directory" ]]; then
        mkdir "$generated_directory"
        if (( EUID == 0 )); then chown "$demo_caller_uid:$demo_caller_gid" "$generated_directory"; fi
    fi
done
demo_root="$(mktemp -d "$PROJECT_ROOT/demo/runs/run.XXXXXX")"
if [[ -n "${DEMO_ARTIFACT_PATH_FILE:-}" ]]; then
    printf '%s\n' "$demo_root" > "$DEMO_ARTIFACT_PATH_FILE"
fi
chmod 755 "$demo_root"
for log in runtime.log observer.log transcript.log startup.log; do : > "$demo_root/$log"; done
session="tails-demo-$$"
tmux_command=(tmux -L "$session")
worker=(env "PATH=$PATH" "PROJECT_ROOT=$PROJECT_ROOT" "TAILS_PDP_BIN=$TAILS_PDP_BIN" "ADM_TOOL_BIN=$ADM_TOOL_BIN" "DEMO_AUTO=$DEMO_AUTO" "DEMO_TIMEOUT_SECONDS=$DEMO_TIMEOUT_SECONDS" "DEMO_CALLER_UID=$demo_caller_uid" "DEMO_CALLER_GID=$demo_caller_gid" "BASH_ENV=" "ENV=" "LD_LIBRARY_PATH=${LD_LIBRARY_PATH:-}" "TERM=${TERM:-xterm-256color}" "NO_COLOR=${NO_COLOR:-}" bash "$PROJECT_ROOT/scripts/demo.sh" --worker "$demo_root")
if (( EUID != 0 )); then worker=("$DEMO_SUDO_BIN" "${worker[@]}"); fi
printf -v worker_command '%q ' bash "$PROJECT_ROOT/scripts/demo/pane.sh" "$demo_root" "$DEMO_AUTO" "${worker[@]}"
printf -v close_command '%q ' "${tmux_command[@]}" kill-session -t demo
worker_command+="; $close_command"
printf -v runtime_command '%q ' tail -n +1 -F "$demo_root/runtime.log"
printf -v observer_command '%q ' tail -n +1 -F "$demo_root/observer.log"

launcher_cleanup() {
    local status=$?
    trap - EXIT INT TERM HUP
    # Closing the private tmux server sends HUP to the worker; its trap cleans up.
    "${tmux_command[@]}" kill-server 2>/dev/null || true
    # The privileged worker needs a moment to stop the runtime and release pins.
    local deadline=$((SECONDS + 12))
    while [[ ! -r "$demo_root/exit-status" ]] && (( SECONDS < deadline )); do sleep 0.1; done
    printf '\nDemo-Dateien und Logs: %s\n' "$demo_root"
    if [[ -r "$demo_root/exit-status" ]]; then
        read -r status < "$demo_root/exit-status"
    elif (( status == 0 )); then
        status=1
    fi
    if (( status != 0 )); then
        printf 'Demo fehlgeschlagen (Status %s).\n' "$status" >&2
        if [[ -s "$demo_root/startup.log" ]]; then tail -n 30 "$demo_root/startup.log" >&2; fi
    fi
    exit "$status"
}
trap launcher_cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP

# Configure everything before the worker starts. No race with an early failure.
"${tmux_command[@]}" -f /dev/null new-session -d -s demo -x 160 -y 45
"${tmux_command[@]}" set-option -g remain-on-exit on
"${tmux_command[@]}" set-option -g mouse on
"${tmux_command[@]}" set-option -g pane-border-status top
"${tmux_command[@]}" set-option -g pane-border-format ' #{pane_title} '
"${tmux_command[@]}" set-option -g status-right 'Enter: weiter | Strg+C: abbrechen | Präfix Strg+B'
"${tmux_command[@]}" set-option -g status 2
if [[ -z "${NO_COLOR:-}" && "${TERM:-dumb}" != dumb ]]; then
    legend='#[default]Legende: #[fg=colour11]$ Eingabe/Befehl #[fg=colour12]Ausgabe #[fg=colour13]Policy/Attribute #[fg=colour10]Prüfung OK #[fg=colour9]Fehler #[fg=colour6,bold]Kapitel#[default]'
else
    legend='Legende: $ = Eingabe/Befehl | Ausgabe = Programmantwort | Policy/Attribute = Quelldatei | OK/Fehler = Demo-Prüfung'
fi
"${tmux_command[@]}" set-option -g 'status-format[1]' "$legend"
"${tmux_command[@]}" split-window -h -p 42 -t demo:0.0 "$runtime_command"
"${tmux_command[@]}" split-window -v -p 42 -t demo:0.1 "$observer_command"
"${tmux_command[@]}" select-pane -t demo:0.0 -T 'Geführte Demo'
"${tmux_command[@]}" select-pane -t demo:0.1 -T 'Runtime / Kernelspace-PEP / Userspace-PEP'
"${tmux_command[@]}" select-pane -t demo:0.2 -T 'FD-Beobachter / Ergebnisse'
"${tmux_command[@]}" respawn-pane -k -t demo:0.0 "$worker_command"
"${tmux_command[@]}" select-pane -t demo:0.0
echo 'Die Demo wird gestartet. Falls erforderlich, links das sudo-Passwort eingeben; danach führt Enter durch die Schritte.'
# An independent server also works when launched inside an existing tmux session.
TMUX= "${tmux_command[@]}" attach-session -t demo

#!/usr/bin/env bash
# Keep failures before the privileged worker starts visible in the tmux pane.
set -uo pipefail
demo_root="$1"
demo_auto="$2"
shift 2

# Preserve stdout as a terminal (the demo uses it to select its colours).
exec 3>&2
startup_pipe="$demo_root/startup.pipe"
mkfifo "$startup_pipe" || exit 1
tee -a "$demo_root/startup.log" < "$startup_pipe" >&3 &
stderr_tee_pid=$!
exec 2> "$startup_pipe"
rm -- "$startup_pipe"
if "$@"; then status=0; else status=$?; fi

if [[ ! -r "$demo_root/exit-status" ]]; then
    # sudo, the shell or unshare may fail before the worker installs its traps.
    if (( status == 0 )); then status=1; fi
    printf '%s\n' "$status" > "$demo_root/exit-status"
    printf '\nDemo-Worker konnte nicht vollständig gestartet werden (Status %s).\nDiagnose: %s/startup.log\n' "$status" "$demo_root" >&2
    if [[ "$demo_auto" == 0 && -t 0 ]]; then
        read -r -p 'Enter: tmux-Demo schließen ' _ || true
    fi
fi
# Flush the log before tmux is closed and its remaining pane processes get HUP.
exec 2>&3 3>&-
wait "$stderr_tee_pid" || true
exit "$status"

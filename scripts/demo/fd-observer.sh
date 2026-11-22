#!/usr/bin/env bash
# Hält echte Bash-Dateideskriptoren offen und zeigt ihren Zustand über /proc.
# Aufruf: bash fd-observer.sh GESCHÜTZTE_DATEI KONTROLLDATEI AUSGABEVERZEICHNIS
set -Eeuo pipefail

target="$1" safe="$2" directory="$3"
observer_pid=$$
color="${DEMO_OUTPUT_COLOR:-}" reset="${DEMO_COLOR_RESET:-}"
trap 'exit 0' TERM INT

# Unterprozesse dürfen die geschützten FDs nicht erben: Gezeigt wird der
# Entzug im Beobachter selbst, nicht in dessen kurzlebigen Hilfsprogrammen.
# Führt ein Linux-Werkzeug ohne geerbte geschützte oder Kontroll-FDs aus.
without_files() { "$@" 10<&- 11<&- 12<&- 13<&- 14<&-; }
# Kennzeichnet eine Zustandsmeldung für das rechte untere tmux-Fenster.
message() { printf '%s[FD-Beobachter: Bash /proc] %s%s\n' "$color" "$*" "$reset"; }

printf '%s$ echo $UID%s\n' "$color" "$reset"
printf '%s\n' "$UID"
printf '%s$ echo $$%s\n' "$color" "$reset"
printf '%s\n' "$observer_pid"
message "Bash-Prozess PID $observer_pid hält die Dateien offen; er schließt die FDs nicht selbst."
printf '%s$ exec 10<%q%s\n' "$color" "$target" "$reset"
exec 10<"$target"
printf '%s$ exec 11<%q%s\n' "$color" "$target" "$reset"
exec 11<"$target"
printf '%s$ exec 12<%q%s\n' "$color" "$target" "$reset"
exec 12<"$target"
printf '%s$ exec 13<%q%s\n' "$color" "$safe" "$reset"
exec 13<"$safe"
printf '%s$ exec 14<%q%s\n' "$color" "$safe" "$reset"
exec 14<"$safe"
printf '{"pid":%s,"protected":[10,11,12],"controls":[13,14]}\n' "$observer_pid" > "$directory/ready.tmp"
without_files mv -- "$directory/ready.tmp" "$directory/ready.json"

previous=''
while :; do
    states=() descriptions=()
    for fd in 10 11 12 13 14; do
        if [[ -e "/proc/$observer_pid/fd/$fd" ]]; then
            states+=(true)
            descriptions+=("$fd: offen")
        else
            states+=(false)
            descriptions+=("$fd: geschlossen")
        fi
    done
    current="${states[*]}"
    if [[ "$current" != "$previous" ]]; then
        message "PID $observer_pid | Geschützte FDs [${descriptions[0]}, ${descriptions[1]}, ${descriptions[2]}] | Kontroll-FDs [${descriptions[3]}, ${descriptions[4]}] | Prozess läuft"
        printf '%s$ ls -l /proc/%s/fd%s\n' "$color" "$observer_pid" "$reset"
        # The PEP may close another FD while ls is reading the directory.
        without_files ls -l "/proc/$observer_pid/fd" || true
        unix_ns="$(without_files date +%s%N)"
        printf '{"protected":[%s,%s,%s],"controls":[%s,%s],"unix_ns":%s}\n' \
            "${states[0]}" "${states[1]}" "${states[2]}" "${states[3]}" "${states[4]}" "$unix_ns" > "$directory/state.tmp"
        without_files mv -- "$directory/state.tmp" "$directory/state.json"
        previous="$current"
    fi
    without_files sleep 0.05
done

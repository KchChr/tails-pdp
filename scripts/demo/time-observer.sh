#!/usr/bin/env bash
# Kapitel 9: Öffnet während Permit genau einen FD und hält ihn bis zum Entzug.
# Während Deny folgt höchstens ein echter Öffnungsversuch pro Unix-Sekunde.
# Aufruf: bash time-observer.sh DATEI AUSGABEVERZEICHNIS RUNTIME_LOG
set -Eeuo pipefail
export LC_ALL=C

target="$1" directory="$2" runtime_log="$3"
observer_pid=$$
opens=0 revocations=0 denied=0 attempts=0 held=0 next_attempt=0 previous_second=-1
color="${DEMO_OUTPUT_COLOR:-}" reset="${DEMO_COLOR_RESET:-}"
trap 'exit 0' TERM INT
# Stderr ausdrücklich sichern: Eine temporäre Gruppen-Umleitung könnte Bash
# intern FD 10 verwenden und den gerade geöffneten FD beim Zurücksetzen schließen.
exec 9>&2

# Hilfsprogramme dürfen den im Beobachter gehaltenen FD nicht erben.
without_file() { "$@" 10<&-; }
# Zeigt Öffnungen, Denys und Entzüge in beiden rechten tmux-Bereichen.
message() {
    printf '%s[Zeitfenster %s | PID %s] %s%s\n' "$color" "$now" "$observer_pid" "$*" "$reset"
    printf '[Zeitfenster %s | PID %s] %s\n' "$now" "$observer_pid" "$*" >> "$runtime_log"
}
# Bewahrt Ereignisse für die Prüfung auf; der Zustandsstand wird atomar ersetzt.
record_event() {
    printf '{"event":"%s","unix_ns":%s,"pid":%s,"fd":10}\n' \
        "$1" "$unix_ns" "$observer_pid" >> "$directory/events.jsonl"
    printf '{"opens":%s,"revocations":%s,"denied":%s}\n' \
        "$opens" "$revocations" "$denied" > "$directory/state.tmp"
    without_file mv -- "$directory/state.tmp" "$directory/state.json"
}

printf '$ echo $UID\n%s\n$ echo $$\n%s\n' "$UID" "$observer_pid"
printf '{"pid":%s,"fd":10}\n' "$observer_pid" > "$directory/ready.json"
while :; do
    unix_ns="$(without_file date +%s%N)"
    now=$((unix_ns / 1000000000))
    if (( held )) && [[ ! -e "/proc/$observer_pid/fd/10" ]]; then
        held=0
        revocations=$((revocations + 1))
        message 'FD 10 wurde entzogen; derselbe Prozess läuft weiter.'
        record_event revoked
    fi
    if (( held == 0 && now >= next_attempt )); then
        attempts=$((attempts + 1))
        next_attempt=$((now + 1))
        printf '%s$ exec 10<%q%s\n' "$color" "$target" "$reset"
        message "Öffnungsversuch $attempts: exec 10<$(printf '%q' "$target")"
        status=0
        exec 2> "$directory/open.stderr"
        if exec 10<"$target"; then
            exec 2>&9
            held=1
            opens=$((opens + 1))
            message 'Datei geöffnet: FD 10 bleibt bis zum Enforcement offen.'
            record_event opened
            printf '$ ls -l /proc/%s/fd/10\n' "$observer_pid"
            without_file ls -l "/proc/$observer_pid/fd/10" || true
        else
            status=$?
            exec 2>&9
            printf '%s\n' "$(< "$directory/open.stderr")" >&2
            if [[ "$status" != 1 ]] || ! without_file grep -Fq 'Operation not permitted' "$directory/open.stderr"; then
                message "Öffnungsversuch fehlgeschlagen (Status $status); kein nachgewiesener Policy-Deny."
                exit 1
            fi
            denied=$((denied + 1))
            message 'Dateiöffnung verweigert; nächster Versuch in einer Sekunde.'
            record_event denied
        fi
    fi
    if (( held && now != previous_second )); then
        printf '%s[PID %s] FD 10 offen | environment.time %% 20 == %s | Prozess läuft%s\n' \
            "$color" "$observer_pid" "$((now % 20))" "$reset"
    fi
    previous_second="$now"
    without_file sleep 0.1
done

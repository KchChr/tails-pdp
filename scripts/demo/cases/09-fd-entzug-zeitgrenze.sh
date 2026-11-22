#!/usr/bin/env bash
# Kapitel 9: Zehn Sekunden Permit und zehn Sekunden Deny wechseln sich ab.
# Derselbe Bash-Prozess hält FD 10 bis zum zeitgetriggerten Enforcement.
# Danach versucht er jede Sekunde erneut zu öffnen, ohne selbst den FD zu schließen.

    chapter_start '9. Wiederkehrende Zeitfenster: Datei öffnen, offen halten und FD entziehen'

    #Seite 1
    chapter_section 'Ausgangslage' \
        'Die Zeitbedingung environment.time % 20 >= 10 teilt jeden Zyklus in zehn Sekunden Permit und zehn Sekunden Deny.'
    chapter_section 'Aktion' \
        'Ein Bash-Prozess versucht jede Sekunde, die Datei zu öffnen. Sobald dies erlaubt ist, hält er FD 10 offen. Nach dessen Entzug versucht derselbe Prozess erneut jede Sekunde, die Datei zu öffnen.'
    chapter_section 'Erwartetes Verhalten' \
        'An der Deny-Grenze entzieht der Userspace-PEP den offenen FD. In den folgenden zehn Sekunden verweigert der Kernel die Öffnungsversuche. Im nächsten Permit-Fenster bleibt die Datei wieder ungefähr zehn Sekunden offen, bis der nächste FD-Entzug erfolgt.'
    chapter_section 'Hinweis' \
        'Rechts oben: Öffnungsversuche, Kernel-Denys und FD-Entzüge des Userspace-PEP. Rechts unten: laufender Prozess und offener FD. Der erste Zeitabschnitt kann bereits angebrochen sein. Die Vorführung läuft bis zum zweiten FD-Entzug ohne Enter-Pause weiter.'
    printf '\n'
    pause_demo
    policy timed deny '    environment.time % 20 >= 10;'
    admin show-active
    show_request bash "$UID" "$target"

    probe_dir="$(mktemp -d "$demo_root/time-fd.XXXXXX")"
    local before offset deadline
    before="$(generations)"
    offset="$(wc -l < "$demo_root/runtime.log")"
    show_command bash "$PROJECT_ROOT/scripts/demo/time-observer.sh" "$target" "$probe_dir" "$demo_root/runtime.log"
    DEMO_OUTPUT_COLOR="$color_output" DEMO_COLOR_RESET="$color_reset" \
        bash "$PROJECT_ROOT/scripts/demo/time-observer.sh" "$target" "$probe_dir" "$demo_root/runtime.log" >> "$demo_root/observer.log" 2>&1 &
    probe_pid=$!

    # Je nach Startzeit dauert die Folge bis zu 40 Sekunden; zusätzliche Zeit
    # bleibt für Einrichtung und Scans auf dem Zielsystem.
    deadline=$((SECONDS + 40 + DEMO_TIMEOUT_SECONDS))
    while :; do
        alive || { fail 'Runtime während des Zeitfenster-Falls beendet.'; return 1; }
        kill -0 "$probe_pid" 2>/dev/null || { fail 'Zeitbeobachter unerwartet beendet; siehe FD-Beobachter.'; return 1; }
        if [[ -f "$probe_dir/state.json" ]] && python3 - "$probe_dir/state.json" <<'PY_CHECK'
import json, sys
state = json.load(open(sys.argv[1]))
raise SystemExit(0 if state['opens'] >= 2 and state['revocations'] >= 2 else 1)
PY_CHECK
        then
            break
        fi
        (( SECONDS < deadline )) || { fail 'Zwei zeitgetriggerte FD-Entzüge sind ausgeblieben.'; return 1; }
        sleep 0.1
    done
    # Die FD-Beobachtung kann der Logausgabe des PEP knapp zuvorkommen.
    deadline=$((SECONDS + DEMO_TIMEOUT_SECONDS))
    while [[ "$(grep -Fc "USERSPACE_PEP closed pid=$probe_pid fd=10 " "$demo_root/runtime.log")" -lt 2 ]]; do
        alive || { fail 'Runtime vor dem Logging der FD-Entzüge beendet.'; return 1; }
        (( SECONDS < deadline )) || { fail 'Zwei FD-Entzüge fehlen im Userspace-PEP-Log.'; return 1; }
        sleep 0.1
    done
    [[ "$(generations)" == "$before" ]] || { fail 'Konfigurationsgeneration während der Zeitfenster verändert.'; return 1; }
    python3 "$PROJECT_ROOT/scripts/demo/time-observer-check.py" \
        "$probe_dir" "$demo_root/runtime.log" "$offset" "$probe_pid"


    #Seite 2
    step 'Policy entfernen:.'
    stop_probe
    remove_policy timed
    show_request cat "$UID" "$target"
    run_cmd 'echo $UID'
    #run_cmd "stat -Lc 'Device (Major:Minor): %Hd:%Ld | Inode: %i' $(printf '%q' "$target")"
    run_cmd "cat $(printf '%q' "$target")"
    show_decision allow allow "$target"

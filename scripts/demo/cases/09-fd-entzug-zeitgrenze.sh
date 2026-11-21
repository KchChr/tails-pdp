#!/usr/bin/env bash
# Kapitel 9: Erst nach der Enter-Pause die Grenze berechnen. Ab dem Öffnen
# nichts mehr veröffentlichen; Zeit-Trigger und konstante Generationen prüfen.
# Wird in demo_worker eingebunden und nutzt dessen Runtime und Arbeitsbereich.

    chapter_start '9. FD-Entzug ausschließlich durch eine Zeitgrenze'

    #Seite 1
    chapter_section 'Ausgangslage' \
        'Eine Zeitbedingung kann ihren Wahrheitswert ändern, ohne dass eine Policy oder ein Attribut veröffentlicht wird.'
    chapter_section 'Aktion' \
        'Nach dem Drücken der Enter-Taste wird eine Grenze zwölf Sekunden in der Zukunft berechnet. Die zeitabhängige Policy wird geladen und die Dateien werden vor dieser Grenze geöffnet. Anschließend wird ohne eine weitere Konfigurationsänderung gewartet.'
    chapter_section 'Erwartetes Verhalten' \
        'Vor der Grenze sind die FDs offen. Nach Erreichen der Grenze wird die Deny-Bedingung wahr und ein zeitgetriggerter Scan entzieht die drei geschützten FDs. Beide Konfigurationsgenerationen bleiben gleich.'
    chapter_section 'Hinweis' \
        'Während des Zeitübergangs läuft die Demo ohne Enter-Pause weiter; die FDs werden vor und nach der Zeitgrenze geprüft.'
    printf '\n'
    pause_demo
    local boundary
    boundary=$(( $(date +%s) + 12 ))
    (( boundary < 4294967296 )) || { fail 'Zeitgrenze außerhalb des Demo-Modulus.'; return 1; }
    policy timed deny "    environment.time % 4294967296 >= $boundary;"
    start_probe
    assert_probe_identity
    (( $(date +%s) < boundary - 2 )) || { fail 'Einrichtung zu langsam: Zeitgrenze schon zu nah.'; return 1; }
    show_request cat "$UID" "$target"
    run_cmd 'echo $UID'
    run_cmd "stat -Lc 'Device (Major:Minor): %Hd:%Ld | Inode: %i' $(printf '%q' "$target")"
    run_cmd "cat $(printf '%q' "$target")"
    show_decision allow allow "$target"
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
    show_request cat "$UID" "$target"
    run_cmd 'echo $UID'
    run_cmd "stat -Lc 'Device (Major:Minor): %Hd:%Ld | Inode: %i' $(printf '%q' "$target")"
    status=0
    LC_ALL=C run_cmd "cat $(printf '%q' "$target")" 2> "$demo_root/command.stderr" || status=$?
    printf '%s\n' "$(< "$demo_root/command.stderr")" >&2
    if [[ "$status" != 1 ]] || ! grep -Fq 'Operation not permitted' "$demo_root/command.stderr"; then
        fail 'cat wurde nicht wie erwartet durch die Policy verweigert.'
        return 1
    fi
    show_decision deny deny "$target"


    #Seite 2
    step 'Der Zeitauslöser, die unveränderten Generationen und der FD-Entzug sind bestätigt. Der Beobachter wird beendet und die Policy entfernt; danach muss eine neue Dateiöffnung wieder erlaubt sein.'
    stop_probe
    remove_policy timed
    show_request cat "$UID" "$target"
    run_cmd 'echo $UID'
    run_cmd "stat -Lc 'Device (Major:Minor): %Hd:%Ld | Inode: %i' $(printf '%q' "$target")"
    run_cmd "cat $(printf '%q' "$target")"
    show_decision allow allow "$target"

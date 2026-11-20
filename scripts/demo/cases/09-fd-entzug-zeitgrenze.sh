#!/usr/bin/env bash
# Kapitel 9: Erst nach der Enter-Pause die Grenze berechnen. Ab dem Öffnen
# nichts mehr veröffentlichen; Zeit-Trigger und konstante Generationen prüfen.
# Wird in demo_worker eingebunden und nutzt dessen Runtime und Arbeitsbereich.

    chapter_start '9. FD-Entzug ausschließlich durch eine Zeitgrenze'
    chapter_section 'Ausgangslage' \
        'Eine Zeitbedingung kann ihren Wahrheitswert ändern, ohne dass jemand eine Policy oder ein Attribut veröffentlicht.'
    chapter_section 'Aktion' \
        'Nach dem Drücken der Enter-Taste wird eine Grenze zwölf Sekunden in der Zukunft berechnet. Die zeitabhängige Policy wird geladen und die Dateien werden vor dieser Grenze geöffnet. Anschließend wird ohne weitere Konfigurationsänderung gewartet.'
    chapter_section 'Erwartetes Verhalten' \
        'Vor der Grenze sind die FDs offen. Nach Erreichen der Grenze wird die Deny-Bedingung wahr und ein zeitgetriggerter Scan entzieht die drei geschützten FDs. Beide Konfigurationsgenerationen bleiben gleich.'
    chapter_section 'Beobachtung' \
        'Die Uhr wird nicht verstellt. Der große Modulus 4294967296 macht den Vergleich in der aktuellen Unix-Epoche zu einem einmaligen nahen Übergang. Im Log ist time:<Zeitgrenze> der Auslöser. Während dieser zwölf Sekunden gibt es keine weitere Enter-Pause.'
    printf '\n'
    pause_demo
    local boundary
    boundary=$(( $(date +%s) + 12 ))
    (( boundary < 4294967296 )) || { fail 'Zeitgrenze außerhalb des Demo-Modulus.'; return 1; }
    policy timed deny "    environment.time % 4294967296 >= $boundary;"
    start_probe
    assert_probe_identity
    (( $(date +%s) < boundary - 2 )) || { fail 'Einrichtung zu langsam: Zeitgrenze schon zu nah.'; return 1; }
    command_access_is allow cat -
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
    command_access_is deny cat -
    step 'Der Zeitauslöser, die unveränderten Generationen und der FD-Entzug sind bestätigt. Der Beobachter wird beendet und die Policy entfernt; danach muss eine neue Dateiöffnung wieder erlaubt sein.'
    stop_probe
    remove_policy timed
    command_access_is allow cat -

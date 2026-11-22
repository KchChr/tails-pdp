#!/usr/bin/env bash
# Kapitel 8: Deny ist bereits geladen, seine Bedingung aber zunächst falsch.
# Nur die Attributgeneration darf sich durch den Auslöser ändern.
# Wird in demo_worker eingebunden und nutzt dessen Runtime und Arbeitsbereich.

    chapter_start '8. FD-Entzug ausschließlich durch Attributänderung'

    #Seite 1
    chapter_section 'Ausgangslage' \
        'Im Authorization Context gilt system.defcon == 5. Vor dem Öffnen wird eine Deny-Policy mit system.defcon <= 2 installiert. Die Policy ist aktiviert, ihre Bedingung ist jedoch noch nicht erfüllt.'
    chapter_section 'Aktion' \
        'Ein neuer Beobachter öffnet drei geschützte und zwei Kontroll-FDs. Danach wird im nächsten Schritt ausschließlich das Systemattribut geändert.'
    chapter_section 'Erwartetes Verhalten' \
        'Solange system.defcon == 5 gilt, bleiben alle FDs offen. Der spätere Wechsel auf system.defcon == 2 muss den Entzug ohne Änderung der Policydatei auslösen.'
    printf '\n'
    pause_demo
    policy revoke deny '    system.defcon <= 2;'
    start_probe


    #Seite 2
    chapter_start '8a. Nur das Systemattribut ändern'
    chapter_section 'Ausgangslage' \
        'Die Policy ist bereits geladen und der Beobachter hält seine FDs offen.'
    chapter_section 'Aktion' \
        'Mit Enter wird ausschließlich defcon = 2 in der Systemattributdatei veröffentlicht. Anschließend gilt im Authorization Context system.defcon == 2. Der Attributloader aktiviert den neuen Wert und löst damit eine Re-evaluation der bestehenden FDs aus.'
    chapter_section 'Erwartetes Verhalten' \
        'Die Attributgeneration steigt, die Policygeneration bleibt gleich. Nur die drei geschützten FDs werden geschlossen; beide Kontroll-FDs bleiben offen.'
    printf '\n'
    admin
    pause_demo
    assert_probe_identity
    before="$(generations)"
    offset="$(wc -l < "$demo_root/runtime.log")"
    attribute_before="$(generations)"
    attribute_offset="$(wc -l < "$demo_root/runtime.log")"
    run_cmd "echo \"defcon = 2\" > $(printf '%q' "$attribute_dir/system.attributes.tmp")"
    run_cmd "mv -f -- $(printf '%q' "$attribute_dir/system.attributes.tmp") $(printf '%q' "$attribute_dir/system.attributes")"
    wait_generation attribute "${attribute_before##* }" "$attribute_offset"
    show_policy_context
    local current
    current="$(generations)"
    [[ "${before%% *}" == "${current%% *}" ]] || { fail 'Policygeneration unerwartet geändert.'; return 1; }
    wait_log "scan started cause=[attributes:${current##* }]" "$offset"
    expect_revoked


    #Seite 3
    step 'Löschen der Policy.'
    stop_probe
    remove_policy revoke

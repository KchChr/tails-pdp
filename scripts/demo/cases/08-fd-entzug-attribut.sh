#!/usr/bin/env bash
# Kapitel 8: Deny ist bereits geladen, seine Bedingung aber zunächst falsch.
# Nur die Attributgeneration darf sich durch den Auslöser ändern.
# Wird in demo_worker eingebunden und nutzt dessen Runtime und Arbeitsbereich.

    chapter_start '8. FD-Entzug ausschließlich durch Attributänderung'
    chapter_section 'Ausgangslage' \
        'Im Authorization Context gilt `system.defcon == 5;`. Vor dem Öffnen wird eine Deny-Policy mit `system.defcon <= 2;` installiert. Die Policy ist aktiviert, ihre Bedingung ist jedoch noch nicht erfüllt.'
    chapter_section 'Aktion' \
        'Ein neuer Beobachter öffnet drei geschützte und zwei Kontroll-FDs. Danach wird im nächsten Schritt ausschließlich das Systemattribut geändert.'
    chapter_section 'Erwartetes Verhalten' \
        'Solange `system.defcon == 5;` gilt, bleiben alle FDs offen. Der spätere Wechsel auf `system.defcon == 2;` muss den Entzug ohne Änderung der Policydatei auslösen.'
    printf '\n'
    pause_demo
    policy revoke deny '    system.defcon <= 2;'
    start_probe
    chapter_start '8a. Nur das Systemattribut ändern'
    chapter_section 'Ausgangslage' \
        'Die Policy ist bereits geladen und der Beobachter hält seine FDs offen. Die aktuelle Policygeneration wird gespeichert.'
    chapter_section 'Aktion' \
        'Mit Enter wird ausschließlich defcon = 2 in der Systemattributdatei veröffentlicht. Anschließend gilt im Authorization Context `system.defcon == 2;`. Der Attributloader aktiviert den neuen Wert und löst damit eine Re-evaluation der bestehenden FDs aus.'
    chapter_section 'Erwartetes Verhalten' \
        'Die Attributgeneration steigt, die Policygeneration bleibt gleich. Nur die drei geschützten FDs werden geschlossen; beide Kontroll-FDs bleiben offen.'
    printf '\n'
    pause_demo
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

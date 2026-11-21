#!/usr/bin/env bash
# Kapitel 6: Syntax-/Validierungsfehler dürfen keine neue Generation
# aktivieren. Nach der Ablehnung muss eine gültige Korrektur weiter möglich sein.
# Wird in demo_worker eingebunden und nutzt dessen Runtime und Arbeitsbereich.

    chapter_start '6. Ungültige Updates und anschließende Korrektur'

    #Seite 1
    chapter_section 'Ausgangslage' \
        'Es gilt `system.defcon == 2;`. Eine passende Deny-Policy wird geladen. Vor jedem fehlerhaften Update werden beide Generationsnummern gespeichert.'
    chapter_section 'Aktion' \
        'Zuerst wird eine Policy mit fehlendem Semikolon veröffentlicht. Nach ihrer Korrektur wird in der Systemattributdatei defcon = 9 veröffentlicht, obwohl für dieses Attribut nur 1 bis 5 zulässig sind.'
    chapter_section 'Erwartetes Verhalten' \
        'Beide fehlerhaften Updates werden verworfen. Die zuletzt gültigen Generationen und das wirksame Deny bleiben erhalten. Gültige Korrekturen werden anschließend wieder übernommen.'
    printf '\n'
    pause_demo
    policy robust deny '    system.defcon <= 2;'
    local before offset
    explain 'Aktiver Ausgangszustand vor der ungültigen Policy: Die Deny-Policy robust ist aktiviert und im Authorization Context gilt `system.defcon == 2;`.'
    admin show-active
    before="$(generations)"
    offset="$(wc -l < "$demo_root/runtime.log")"


    #Seite 2
    step 'Laden einer syntaktisch fehlerhaften Policy.'
    printf 'policy "broken"\ndeny\n action == "file_open"\n' | publish "$policy_dir/broken.policy"
    wait_log 'POLICY sync failed' "$offset"
    [[ "$(generations)" == "$before" ]] || { fail 'Ungültige Policy änderte die Generation.'; return 1; }
    explain 'Aktiver Zustand nach der Ablehnung: broken wurde nicht aktiviert. Policies, Attribute und beide Generationen bleiben unverändert.'
    admin show-active
    observe "Ungültige Policy verworfen: Policygeneration ${before%% *} und Attributgeneration ${before##* } unverändert."
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


    #Seite 3
    step 'Die fehlerhafte Datei wird entfernt und eine gültige Permit-Policy namens corrected veröffentlicht. Die bereits aktivierte Deny-Policy hat weiterhin Vorrang.'
    remove_policy broken
    policy corrected permit
    explain 'Nach der gültigen Policy-Korrektur ist corrected zusätzlich aktiviert. Die Deny-Policy robust gilt weiterhin.'
    admin show-active
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


    #Seite 4
    step 'Die korrigierte Policy corrected wird entfernt. Danach wird der aktive Ausgangszustand für die Attributprüfung angezeigt.'
    remove_policy corrected
    explain 'Aktiver Ausgangszustand vor dem ungültigen Attribut: corrected wurde wieder entfernt. Die Deny-Policy robust und der Kontextwert `system.defcon == 2;` bleiben aktiv.'
    admin show-active
    before="$(generations)"
    offset="$(wc -l < "$demo_root/runtime.log")"


    #Seite 5
    step 'Die Zuweisung defcon = 9 in system.attributes ist nicht erlaubt. Im Authorization Context muss trotz geänderter Quelldatei `system.defcon == 2;` gelten.'
    printf 'defcon = 9\n' | publish "$attribute_dir/system.attributes"
    wait_log 'Ignoring invalid stream attributes' "$offset"
    [[ "$(generations)" == "$before" ]] || { fail 'Ungültiges Attribut änderte die Generation.'; return 1; }
    explain 'Aktiver Zustand nach der Ablehnung von defcon = 9: show-active zeigt weiterhin den Wert 2 für system.defcon sowie dieselben Policies und Generationen.'
    admin show-active
    observe "Ungültiges Attribut verworfen: Policygeneration ${before%% *} und Attributgeneration ${before##* } unverändert."
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


    #Seite 6
    step 'Mit dem gültigen Wert 5 wird ein neuer Attributstand aktiviert. Die Deny-Bedingung ist danach falsch und der Zugriff wieder erlaubt.'
    attribute system.attributes 'defcon = 5'
    explain 'Aktiver Zustand nach der gültigen Attribut-Korrektur: Der Kontextwert `system.defcon == 5;` und die neue Attributgeneration sind sichtbar. Die Deny-Policy robust ist weiterhin aktiviert, ihre Bedingung ist jetzt jedoch falsch.'
    admin show-active
    show_request cat "$UID" "$target"
    run_cmd 'echo $UID'
    run_cmd "stat -Lc 'Device (Major:Minor): %Hd:%Ld | Inode: %i' $(printf '%q' "$target")"
    run_cmd "cat $(printf '%q' "$target")"
    show_decision allow allow "$target"


    #Seite 7
    step 'Die Demo-Policy wird entfernt.'
    remove_policy robust

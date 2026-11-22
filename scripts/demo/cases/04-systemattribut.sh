#!/usr/bin/env bash
# Kapitel 4: Bei unveränderter Policy die Authorization Decision allein über einen
# Systemattributwert ändern; Attribut- und Policygeneration sind getrennt.
# Wird in demo_worker eingebunden und nutzt dessen Runtime und Arbeitsbereich.

    chapter_start '4. Dynamisches Systemattribut'

    #Seite 1
    chapter_section 'Ausgangslage' \
        '`system.defcon == 5;`. .'
    chapter_section 'Aktion' \
        'Eine Deny-Policy mit `system.defcon <= 2;` wird geladen. Anschließend wird system.defcon von 5 auf 2 und zurück auf 5 geändert.'
    chapter_section 'Erwartetes Verhalten' \
        'Bei `system.defcon == 5;` ist die Deny-Bedingung nicht erfüllt und der Zugriff erlaubt. Bei `system.defcon == 2;` ist sie erfüllt und der wird Zugriff verweigert. Nach der Rückkehr zu `system.defcon == 5;` ist er wieder erlaubt.'
    printf '\n'
    pause_demo
    policy context deny '    system.defcon <= 2;'
    admin
    show_request cat "$UID" "$target"
    run_cmd 'echo $UID'
    #run_cmd "stat -Lc 'Device (Major:Minor): %Hd:%Ld | Inode: %i' $(printf '%q' "$target")"
    run_cmd "cat $(printf '%q' "$target")"


    #Seite 2
    step ' Es gilt `system.defcon == 2`.  Die bereits geladene Deny-Policy trifft jetzt zu.'
    attribute system.attributes 'defcon = 2'
    show_request cat "$UID" "$target"
    run_cmd 'echo $UID'
    #run_cmd "stat -Lc 'Device (Major:Minor): %Hd:%Ld | Inode: %i' $(printf '%q' "$target")"
    status=0
    LC_ALL=C run_cmd "cat $(printf '%q' "$target")" 2> "$demo_root/command.stderr" || status=$?
    printf '%s\n' "$(< "$demo_root/command.stderr")" >&2
    if [[ "$status" != 1 ]] || ! grep -Fq 'Operation not permitted' "$demo_root/command.stderr"; then
        fail 'cat wurde nicht wie erwartet durch die Policy verweigert.'
        return 1
    fi
    admin show-active


    #Seite 3
    step 'Es gilt wieder `system.defcon == 5;`. Dieselbe Policy trifft nicht mehr zu.'
    attribute system.attributes 'defcon = 5'
    show_request cat "$UID" "$target"
    run_cmd 'echo $UID'
    #run_cmd "stat -Lc 'Device (Major:Minor): %Hd:%Ld | Inode: %i' $(printf '%q' "$target")"
    run_cmd "cat $(printf '%q' "$target")"


    #Seite 4
    step 'Die Demo-Policy dieses Kapitels wird entfernt.'
    remove_policy context

#!/usr/bin/env bash
# Kapitel 10: UTC-Felder ergänzen die Modulo-Demo. Immer wahre Vergleiche
# vermeiden eine Abhängigkeit von der Vorführungszeit und zeigen Deny-Vorrang.
# Wird in demo_worker eingebunden und nutzt dessen Runtime und Arbeitsbereich.

    chapter_start '10. UTC-Zeitbedingung und abschließende Inspektion'

    #Seite 1
    chapter_section 'Ausgangslage' \
        'Neben Unix-Zeit mit Modulus unterstützt der Prototyp UTC-Zeitfelder.'
    chapter_section 'Aktion' \
        'Zuerst wird eine Permit-Policy mit environment.utc.minute >= 0 geladen und der Zugriff geprüft. Danach kommt eine Deny-Policy mit environment.utc.hour >= 0 hinzu.'
    chapter_section 'Erwartetes Verhalten' \
        'Beide Bedingungen sind jederzeit wahr. Da Deny Vorrang hat, wird der Zugriff verweigert.'
    printf '\n'
    pause_demo
    policy stream-permit permit '    environment.utc.minute >= 0;'
    show_request cat "$UID" "$target"
    run_cmd 'echo $UID'
    #run_cmd "stat -Lc 'Device (Major:Minor): %Hd:%Ld | Inode: %i' $(printf '%q' "$target")"
    run_cmd "cat $(printf '%q' "$target")"
    show_decision allow allow "$target"


    #Seite 2
    step 'Die zusätzliche UTC-Deny-Policy wird veröffentlicht.'
    policy utc deny '    environment.utc.hour >= 0;'
    explain 'Die zusätzliche UTC-Deny-Policy hat Vorrang.'
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
    show_decision deny deny "$target"
    admin

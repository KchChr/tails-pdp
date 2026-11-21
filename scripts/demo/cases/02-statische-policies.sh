#!/usr/bin/env bash
# Kapitel 2: Echte Programme und Benutzeridentitäten variieren jeweils einen Filter.
# Vor der Policy werden beide Benutzer geprüft, damit normale Dateirechte den Vergleich nicht verfälschen.
# Der Hardlink belegt zusätzlich den Abgleich über Gerät und Inode.

    chapter_start '2. Statische Policies: Kommando, Benutzer und Ressource'
    #Seite 1
    chapter_section 'Ausgangslage' \
        "relevante Dateien:
  $target
  $safe
  ${target%/*}/alias.txt"
    chapter_section 'Aktion' \
        'Eine Deny-Policy wird veröffentlicht. Danach werden subject.uid, command und resource einzeln variiert.'

    chapter_section 'Erwartetes Verhalten' \
        'Deny bei Übereinstimmung aller Attribute, ansonsten Permit'
    printf '\n'
    pause_demo
    explain "Die Datei $target wird mit UID = $UID und cat geöffnet:"
    run_cmd 'echo $UID'
    run_cmd "stat -Lc 'Device (Major:Minor): %Hd:%Ld | Inode: %i' $(printf '%q' "$target")"
    run_cmd "cat $(printf '%q' "$target")"

    #Seite 2
    step 'Auch der Vergleichsbenutzer muss die Datei ohne Policy lesen können.'
    comparison_user="$(id -un "$comparison_uid")"
    run_cmd "sudo -u $(printf '%q' "$comparison_user") -- id -u"
    run_cmd "sudo -u $(printf '%q' "$comparison_user") -- stat -Lc 'Device (Major:Minor): %Hd:%Ld | Inode: %i' $(printf '%q' "$target")"
    run_cmd "sudo -u $(printf '%q' "$comparison_user") -- cat $(printf '%q' "$target")"


    #Seite 3
    step "Die Deny-Policy für subject.uid == ${UID};, command == \"cat\"; und die geschützte Ressource wird veröffentlicht."
    policy scoped deny "    subject.uid == $UID;" cat
    admin show-active
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


    #Seite 4
    step "Nur der Benutzer wird geändert: sudo -u startet cat mit UID = $comparison_uid."
    admin
    show_request cat "$comparison_uid" "$target"
    run_cmd "sudo -u $(printf '%q' "$comparison_user") -- id -u"
    #run_cmd "sudo -u $(printf '%q' "$comparison_user") -- stat -Lc 'Device (Major:Minor): %Hd:%Ld | Inode: %i' $(printf '%q' "$target")"
    run_cmd "sudo -u $(printf '%q' "$comparison_user") -- cat $(printf '%q' "$target")"
    show_decision allow allow "$target"



    #Seite 5
    step 'command == "head";. Die UID bleibt gleich.'
    show_request head "$UID" "$target"
    run_cmd 'echo $UID'
    #run_cmd "stat -Lc 'Device (Major:Minor): %Hd:%Ld | Inode: %i' $(printf '%q' "$target")"
    run_cmd "head $(printf '%q' "$target")"
    show_decision allow allow "$target"





    #Seite 6
    step 'cat auf die Kontrolldatei, der Zugriff muss erlaubt bleiben.'
    show_request cat "$UID" "$safe"
    run_cmd 'echo $UID'
    #run_cmd "stat -Lc 'Device (Major:Minor): %Hd:%Ld | Inode: %i' $(printf '%q' "$safe")"
    run_cmd "cat $(printf '%q' "$safe")"
    show_decision allow allow "$safe"


    #Seite 7
    step "Der alternative Hardlink-Pfad bezeichnet dieselbe geschützte Datei. cat muss auch über diesen Pfad abgewiesen werden."
    alias_path="$PROJECT_ROOT/demo/files/alias.txt"
    show_request cat "$UID" "$alias_path"
    run_cmd 'echo $UID'
    #run_cmd "stat -Lc 'Device (Major:Minor): %Hd:%Ld | Inode: %i' $(printf '%q' "$alias_path")"
    status=0
    LC_ALL=C run_cmd "cat $(printf '%q' "$alias_path")" 2> "$demo_root/command.stderr" || status=$?
    printf '%s\n' "$(< "$demo_root/command.stderr")" >&2
    if [[ "$status" != 1 ]] || ! grep -Fq 'Operation not permitted' "$demo_root/command.stderr"; then
        fail 'cat über den Hardlink wurde nicht wie erwartet durch die Policy verweigert.'
        return 1
    fi
    show_decision deny deny "$alias_path"
    admin show-active

    #Seite 8
    step 'Die Policy wird entfernt. Derselbe zuvor verweigerte Zugriff muss wieder möglich sein.'
    remove_policy scoped
    admin
    show_request cat "$UID" "$target"
    run_cmd 'echo $UID'
    #run_cmd "stat -Lc 'Device (Major:Minor): %Hd:%Ld | Inode: %i' $(printf '%q' "$target")"
    run_cmd "cat $(printf '%q' "$target")"
    show_decision allow allow "$target"

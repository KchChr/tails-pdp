#!/usr/bin/env bash
# Kapitel 5: System-, Subjekt- und Ressourcenattribute sind konjunktiv.
# Fehlende oder anders typisierte Werte erfüllen den Stringvergleich nicht;
# das ist hier ein gültiger Attributstand, kein abgelehntes Update wie in 6.
# Wird in demo_worker eingebunden und nutzt dessen Runtime und Arbeitsbereich.

    chapter_start '5. Subject-/Resource-Attribute und UND-Verknüpfung'

    #Seite 1
    chapter_section 'Ausgangslage' \
        'Attribute können für das gesamte System, für einen Benutzer und für eine konkrete Datei hinterlegt werden. Der normale Demo-Zugriff verwendet subject.uid == 0 .'
    chapter_section 'Aktion' \
        'Der Authorization Context wird vorbereitet: system.defcon == 2, subject.position == "engineer" für subject.uid == 0 und resource.classification == "internal". Eine Deny-Policy verknüpft alle drei Bedingungen mit UND. Danach werden einzelne Werte geändert.'
    chapter_section 'Erwartetes Verhalten' \
        'Deny gilt nur, wenn alle drei Bedingungen erfüllt sind. subject.position == "intern" oder resource.classification == "public" reichen jeweils aus, damit diese Deny-Policy nicht mehr passt.'
    printf '\n'
    pause_demo
    attribute_before="$(generations)"
    attribute_offset="$(wc -l < "$demo_root/runtime.log")"
    run_cmd "echo \"defcon = 2\" > $(printf '%q' "$attribute_dir/system.attributes")"
    wait_generation attribute "${attribute_before##* }" "$attribute_offset"
    show_policy_context
    run_cmd "cat $(printf '%q' "$attribute_dir/system.attributes")"
    attribute subjects/0.attributes 'position = "engineer"'
    run_cmd "cat $(printf '%q' "$attribute_dir/subjects/0.attributes")"
    attribute "resources${target}.attributes" 'classification = "internal"'
    run_cmd "cat $(printf '%q' "$attribute_dir/resources${target}.attributes")"

    policy combined deny $'    system.defcon <= 2;\n    subject.position == "engineer";\n    resource.classification == "internal";'
    admin
    show_request cat "$UID" "$target"
    run_cmd 'echo $UID'
    run_cmd "stat -Lc 'Device (Major:Minor): %Hd:%Ld | Inode: %i' $(printf '%q' "$target")"
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
    step 'subject.position wird geändert subject.position == "engineer" --> subject.position == "intern".'
    attribute subjects/0.attributes 'position = "intern"'
    show_request cat "$UID" "$target"
    run_cmd 'echo $UID'
    run_cmd "stat -Lc 'Device (Major:Minor): %Hd:%Ld | Inode: %i' $(printf '%q' "$target")"
    run_cmd "cat $(printf '%q' "$target")"
    show_decision allow allow "$target"


    #Seite 3
    step 'Es gilt wieder subject.position == "engineer". Alle drei BEdingungen sind erfüllt.'
    attribute subjects/0.attributes 'position = "engineer"'
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
    step ' resource.classification == "internal" --> resource.classification == "public". Die Policy ist somit nicht mehr erfüllt.'
    attribute "resources${target}.attributes" 'classification = "public"'
    show_request cat "$UID" "$target"
    run_cmd 'echo $UID'
    run_cmd "stat -Lc 'Device (Major:Minor): %Hd:%Ld | Inode: %i' $(printf '%q' "$target")"
    run_cmd "cat $(printf '%q' "$target")"
    show_decision allow allow "$target"


    #Seite 5
    step 'resource.classification == "internal" alle drei Bedingungen sind erfüllt.'
    attribute "resources${target}.attributes" 'classification = "internal"'
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
    step 'subject.position fehlt vollständig. Die Veröffentlichung ist gültig; die Bedingung subject.position == "engineer" ist nicht erfüllt.'
    attribute subjects/0.attributes '# position fehlt'
    run_cmd "cat $(printf '%q' "$attribute_dir/subjects/0.attributes")"
    show_request cat "$UID" "$target"
    run_cmd 'echo $UID'
    #run_cmd "stat -Lc 'Device (Major:Minor): %Hd:%Ld | Inode: %i' $(printf '%q' "$target")"
    run_cmd "cat $(printf '%q' "$target")"
    show_decision allow allow "$target"


    #Seite 7
    step 'Es gilt subject.position == 1 statt subject.position == "engineer". Der Integer 1 stimmt nicht mit dem String "engineer" überein.'
    attribute subjects/0.attributes 'position = 1'
    show_request cat "$UID" "$target"
    run_cmd 'echo $UID'
    #run_cmd "stat -Lc 'Device (Major:Minor): %Hd:%Ld | Inode: %i' $(printf '%q' "$target")"
    run_cmd "cat $(printf '%q' "$target")"
    show_decision allow allow "$target"


    #Seite 8
    step 'Es gilt wieder subject.position == "engineer": Alle Bedingungen passen und der Zugriff wird verweigert.'
    attribute subjects/0.attributes 'position = "engineer"'
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


    #Seite 9
    step 'Die Demo-Policy dieses Kapitels wird entfernt.'
    remove_policy combined

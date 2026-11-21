#!/usr/bin/env bash
# Kapitel 5: System-, Subjekt- und Ressourcenattribute sind konjunktiv.
# Fehlende oder anders typisierte Werte erfüllen den Stringvergleich nicht;
# das ist hier ein gültiger Attributstand, kein abgelehntes Update wie in 6.
# Wird in demo_worker eingebunden und nutzt dessen Runtime und Arbeitsbereich.

    chapter_start '5. Subject-/Resource-Attribute und UND-Verknüpfung'

    #Seite 1
    chapter_section 'Ausgangslage' \
        'Attribute können für das gesamte System, für einen Benutzer und für eine konkrete Datei hinterlegt werden. Der normale Demo-Zugriff verwendet `subject.uid == 0;` .'
    chapter_section 'Aktion' \
        'Der Authorization Context wird vorbereitet: `system.defcon == 2;`, `subject.position == "engineer";` für `subject.uid == 0;` und `resource.classification == "internal";`. Eine Deny-Policy verknüpft alle drei Bedingungen mit UND. Danach werden einzelne Werte geändert.'
    chapter_section 'Erwartetes Verhalten' \
        'Deny gilt nur, wenn alle drei Bedingungen erfüllt sind. `subject.position == "intern";` oder `resource.classification == "public";` reichen jeweils aus, damit diese Deny-Policy nicht mehr passt.'
    printf '\n'
    pause_demo
    attribute system.attributes 'defcon = 2'
    attribute subjects/0.attributes 'position = "engineer"'
    attribute "resources${target}.attributes" 'classification = "internal"'
    policy combined deny $'    system.defcon <= 2;\n    subject.position == "engineer";\n    resource.classification == "internal";'
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
    step 'Nur subject.position ändert sich von `subject.position == "engineer";` zu `subject.position == "intern";`. Damit ist eine der drei UND-Bedingungen falsch.'
    attribute subjects/0.attributes 'position = "intern"'
    show_request cat "$UID" "$target"
    run_cmd 'echo $UID'
    run_cmd "stat -Lc 'Device (Major:Minor): %Hd:%Ld | Inode: %i' $(printf '%q' "$target")"
    run_cmd "cat $(printf '%q' "$target")"
    show_decision allow allow "$target"


    #Seite 3
    step 'Im Authorization Context gilt wieder `subject.position == "engineer";`. Damit sind wieder alle drei Bedingungen erfüllt.'
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
    step 'Nur resource.classification ändert sich von `resource.classification == "internal";` zu `resource.classification == "public";`. Damit passt die Deny-Policy nicht mehr.'
    attribute "resources${target}.attributes" 'classification = "public"'
    show_request cat "$UID" "$target"
    run_cmd 'echo $UID'
    run_cmd "stat -Lc 'Device (Major:Minor): %Hd:%Ld | Inode: %i' $(printf '%q' "$target")"
    run_cmd "cat $(printf '%q' "$target")"
    show_decision allow allow "$target"


    #Seite 5
    step 'Mit `resource.classification == "internal";` sind wieder alle drei Bedingungen erfüllt.'
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
    step 'Jetzt fehlt subject.position vollständig. Die Veröffentlichung ist gültig; die Bedingung `subject.position == "engineer";` passt jedoch nicht.'
    attribute subjects/0.attributes '# position fehlt'
    show_request cat "$UID" "$target"
    run_cmd 'echo $UID'
    run_cmd "stat -Lc 'Device (Major:Minor): %Hd:%Ld | Inode: %i' $(printf '%q' "$target")"
    run_cmd "cat $(printf '%q' "$target")"
    show_decision allow allow "$target"


    #Seite 7
    step 'Im Authorization Context gilt `subject.position == 1;` statt `subject.position == "engineer";`. Die Zahl 1 stimmt nicht mit der Zeichenkette "engineer" überein.'
    attribute subjects/0.attributes 'position = 1'
    show_request cat "$UID" "$target"
    run_cmd 'echo $UID'
    run_cmd "stat -Lc 'Device (Major:Minor): %Hd:%Ld | Inode: %i' $(printf '%q' "$target")"
    run_cmd "cat $(printf '%q' "$target")"
    show_decision allow allow "$target"


    #Seite 8
    step 'Im Authorization Context gilt wieder `subject.position == "engineer";`: Alle Bedingungen passen und der Zugriff wird verweigert.'
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
    admin


    #Seite 9
    step 'Die Demo-Policy dieses Kapitels wird entfernt.'
    remove_policy combined

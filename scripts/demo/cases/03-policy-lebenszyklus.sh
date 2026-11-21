#!/usr/bin/env bash
# Kapitel 3: Permit hebt ein gleichzeitig passendes Deny nicht auf.
# Jede Veröffentlichung/Entfernung aktiviert einen neuen vollständigen Stand.
# Wird in demo_worker eingebunden und nutzt dessen Runtime und Arbeitsbereich.

    chapter_start '3. Permit, Deny-Vorrang und Policy-Lebenszyklus'
    chapter_section 'Ausgangslage' \
        'Nach dem Entfernen der vorherigen Policy sind keine Policies aktiviert. Dies wird vor den Änderungen mit show-active angezeigt. In diesem Schritt werden keine Benutzer- oder Kommandofilter verwendet.'
    printf '\nNachweis der Ausgangslage durch das Administrationstool:\n'
    admin --no-label show-active
    printf '\nOhne aktivierte Policies enthält die Ausgabe keine aktivierten Policy-Einträge. Angezeigte Attribute sind davon unabhängig.\n'
    chapter_section 'Aktion' \
        'Zuerst wird eine Permit-Policy geladen, dann eine passende Deny-Policy ergänzt und anschließend nur die Deny-Policy entfernt. Zum Schluss wird auch die Permit-Policy entfernt.'
    chapter_section 'Erwartetes Verhalten' \
        'Die Zugriffe folgen der Reihenfolge erlaubt → verweigert → erlaubt. Bei gleichzeitig passenden Policies hat Deny Vorrang vor Permit.'
    printf '\n'
    pause_demo
    explain 'Zuerst wird eine Permit-Policy geladen. Der Zugriff ist damit erlaubt.'
    policy permit permit
    show_request cat "$UID" "$target"
    run_cmd 'echo $UID'
    run_cmd "stat -Lc 'Device (Major:Minor): %Hd:%Ld | Inode: %i' $(printf '%q' "$target")"
    run_cmd "cat $(printf '%q' "$target")"
    show_decision allow allow "$target"
    step 'Eine passende Deny-Policy wird ergänzt. Bei gleichzeitig passenden Permit- und Deny-Policies hat Deny Vorrang.'
    policy deny deny
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
    step 'Nur die Deny-Policy wird entfernt; die Permit-Policy bleibt geladen. Der Zugriff ist danach wieder erlaubt.'
    remove_policy deny
    show_request cat "$UID" "$target"
    run_cmd 'echo $UID'
    run_cmd "stat -Lc 'Device (Major:Minor): %Hd:%Ld | Inode: %i' $(printf '%q' "$target")"
    run_cmd "cat $(printf '%q' "$target")"
    show_decision allow allow "$target"
    step 'Die Permit-Policy wird zum Abschluss dieses Kapitels entfernt.'
    remove_policy permit

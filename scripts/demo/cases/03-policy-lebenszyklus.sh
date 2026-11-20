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
    chapter_section 'Beobachtung' \
        'Die Policygeneration ändert sich bei den Veröffentlichungen und Entfernungen. Neue Authorization Decisions werden ohne Neustart wirksam. Die Reihenfolge der Dateinamen bestimmt keine Priorität.'
    printf '\n'
    pause_demo
    explain 'Zuerst wird eine Permit-Policy geladen. Der Zugriff ist damit erlaubt.'
    policy permit permit
    access_is allow
    step 'Eine passende Deny-Policy wird ergänzt. Bei gleichzeitig passenden Permit- und Deny-Policies hat Deny Vorrang.'
    policy deny deny
    access_is deny
    admin
    step 'Nur die Deny-Policy wird entfernt; die Permit-Policy bleibt geladen. Der Zugriff ist danach wieder erlaubt.'
    remove_policy deny
    access_is allow
    step 'Die Permit-Policy wird zum Abschluss dieses Kapitels entfernt.'
    remove_policy permit

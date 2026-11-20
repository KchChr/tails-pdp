#!/usr/bin/env bash
# Kapitel 4: Bei unveränderter Policy die Authorization Decision allein über einen
# Systemattributwert ändern; Attribut- und Policygeneration sind getrennt.
# Wird in demo_worker eingebunden und nutzt dessen Runtime und Arbeitsbereich.

    chapter_start '4. Dynamisches Systemattribut'
    chapter_section 'Ausgangslage' \
        'Im Authorization Context gilt `system.defcon == 5;`. Diese Zahl dient als dynamischer Bestandteil des Authorization Context.'
    chapter_section 'Aktion' \
        'Eine Deny-Policy mit `system.defcon <= 2;` wird geladen. Anschließend wird nur der Attributwert von 5 auf 2 und zurück auf 5 geändert.'
    chapter_section 'Erwartetes Verhalten' \
        'Bei `system.defcon == 5;` ist die Deny-Bedingung falsch und der Zugriff erlaubt. Bei `system.defcon == 2;` ist sie erfüllt und der Zugriff verweigert. Nach der Rückkehr zu `system.defcon == 5;` ist er wieder erlaubt.'
    chapter_section 'Beobachtung' \
        'Die Policydatei bleibt während der Attributwechsel gleich. Im Log und im Admin-Tool ändert sich der Attributstand; die Runtime muss dafür nicht neu gestartet werden.'
    printf '\n'
    pause_demo
    policy context deny '    system.defcon <= 2;'
    command_access_is allow cat -
    step 'Im Authorization Context gilt anschließend `system.defcon == 2;`: Die bereits geladene Deny-Policy trifft jetzt zu.'
    attribute system.attributes 'defcon = 2'
    command_access_is deny cat -
    admin show-active
    step 'Im Authorization Context gilt anschließend wieder `system.defcon == 5;`: Dieselbe Policy trifft nicht mehr zu.'
    attribute system.attributes 'defcon = 5'
    command_access_is allow cat -
    step 'Die Demo-Policy dieses Kapitels wird entfernt.'
    remove_policy context

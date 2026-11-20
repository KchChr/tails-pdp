#!/usr/bin/env bash
# Kapitel 5: System-, Subjekt- und Ressourcenattribute sind konjunktiv.
# Fehlende oder anders typisierte Werte erfüllen den Stringvergleich nicht;
# das ist hier ein gültiger Attributstand, kein abgelehntes Update wie in 6.
# Wird in demo_worker eingebunden und nutzt dessen Runtime und Arbeitsbereich.

    chapter_start '5. Subject-/Resource-Attribute und UND-Verknüpfung'
    chapter_section 'Ausgangslage' \
        'Attribute können für das gesamte System, für einen Benutzer und für eine konkrete Datei hinterlegt werden. Der normale Demo-Zugriff verwendet `subject.uid == 0;` (Real-UID).'
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
    command_access_is deny cat -
    step 'Nur subject.position ändert sich von `subject.position == "engineer";` zu `subject.position == "intern";`. Damit ist eine der drei UND-Bedingungen falsch.'
    attribute subjects/0.attributes 'position = "intern"'
    command_access_is allow cat -
    step 'Im Authorization Context gilt wieder `subject.position == "engineer";`. Damit sind wieder alle drei Bedingungen erfüllt.'
    attribute subjects/0.attributes 'position = "engineer"'
    command_access_is deny cat -
    step 'Nur resource.classification ändert sich von `resource.classification == "internal";` zu `resource.classification == "public";`. Damit passt die Deny-Policy nicht mehr.'
    attribute "resources${target}.attributes" 'classification = "public"'
    command_access_is allow cat -
    step 'Mit `resource.classification == "internal";` sind wieder alle drei Bedingungen erfüllt.'
    attribute "resources${target}.attributes" 'classification = "internal"'
    command_access_is deny cat -
    step 'Jetzt fehlt subject.position vollständig. Die Veröffentlichung ist gültig; die Bedingung `subject.position == "engineer";` passt jedoch nicht.'
    attribute subjects/0.attributes '# position fehlt'
    command_access_is allow cat -
    step 'Im Authorization Context gilt `subject.position == 1;` statt `subject.position == "engineer";`. Die Zahl 1 stimmt nicht mit der Zeichenkette "engineer" überein.'
    attribute subjects/0.attributes 'position = 1'
    command_access_is allow cat -
    step 'Im Authorization Context gilt wieder `subject.position == "engineer";`: Alle Bedingungen passen und der Zugriff wird verweigert.'
    attribute subjects/0.attributes 'position = "engineer"'
    command_access_is deny cat -
    admin
    step 'Die Demo-Policy dieses Kapitels wird entfernt.'
    remove_policy combined

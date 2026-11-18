#!/usr/bin/env bash
# Kapitel 5: System-, Subjekt- und Ressourcenattribute sind konjunktiv.
# Fehlende oder anders typisierte Werte erfüllen den Stringvergleich nicht;
# das ist hier ein gültiger Attributstand, kein abgelehntes Update wie in 6.
# Wird in demo_worker eingebunden und nutzt dessen Runtime und Arbeitsbereich.

    chapter_start '5. Subject-/Resource-Attribute und UND-Verknüpfung'
    chapter_section 'Ausgangslage' \
        'Attribute können für das gesamte System, für einen Benutzer und für eine konkrete Datei hinterlegt werden. Der normale Demo-Zugriff läuft mit Real-UID 0.'
    chapter_section 'Aktion' \
        'DEFCON wird auf 2, die Rolle von UID 0 auf engineer und die Dateiklassifikation auf internal gesetzt. Eine Deny-Policy verknüpft alle drei Bedingungen mit UND. Danach werden einzelne Werte geändert.'
    chapter_section 'Erwartetes Verhalten' \
        'Deny gilt nur, wenn alle drei Bedingungen erfüllt sind. Rolle intern oder Klassifikation public reichen jeweils aus, damit diese Deny-Policy nicht mehr passt.'
    chapter_section 'Beobachtung' \
        'Anschließend wird das Attribut position zunächst weggelassen und danach auf die Zahl 1 statt auf die Zeichenkette "engineer" gesetzt. Beide Attributstände sind gültig, erfüllen aber den Vergleich mit "engineer" nicht. Deshalb greift hier kein Deny.'
    printf '\n'
    pause_demo
    attribute system.attributes 'defcon = 2'
    attribute subjects/0.attributes 'position = "engineer"'
    attribute "resources${target}.attributes" 'classification = "internal"'
    policy combined deny $'    system.defcon <= 2;\n    subject.position == "engineer";\n    resource.classification == "internal";'
    access_is deny
    step 'Nur die Rolle wird von engineer auf intern geändert. Damit ist eine der drei UND-Bedingungen falsch.'
    attribute subjects/0.attributes 'position = "intern"'
    access_is allow
    step 'Die Rolle wird auf engineer zurückgesetzt. Damit sind wieder alle drei Bedingungen erfüllt.'
    attribute subjects/0.attributes 'position = "engineer"'
    access_is deny
    step 'Jetzt wird nur die Dateiklassifikation von internal auf public geändert. Damit passt die Deny-Policy nicht mehr.'
    attribute "resources${target}.attributes" 'classification = "public"'
    access_is allow
    step 'Mit classification=internal sind wieder alle drei Bedingungen erfüllt.'
    attribute "resources${target}.attributes" 'classification = "internal"'
    access_is deny
    step 'Jetzt fehlt position vollständig. Die Veröffentlichung ist gültig, der Rollenvergleich ergibt aber keinen Treffer.'
    attribute subjects/0.attributes '# position fehlt'
    access_is allow
    step 'position wird auf die Zahl 1 statt auf eine Zeichenkette gesetzt. Die Zahl 1 stimmt nicht mit der Zeichenkette "engineer" überein.'
    attribute subjects/0.attributes 'position = 1'
    access_is allow
    step 'position wird wieder auf die Zeichenkette "engineer" gesetzt: Alle Bedingungen passen und der Zugriff wird verweigert.'
    attribute subjects/0.attributes 'position = "engineer"'
    access_is deny
    admin
    step 'Die Demo-Policy dieses Kapitels wird entfernt.'
    remove_policy combined

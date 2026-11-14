#!/usr/bin/env bash
# Kapitel 10: UTC-Felder ergänzen die Modulo-Demo. Immer wahre Vergleiche
# vermeiden eine Abhängigkeit von der Vorführungszeit und zeigen Deny-Vorrang.
# Wird in demo_worker eingebunden und nutzt dessen Runtime und Arbeitsbereich.

    chapter '10. UTC-Zeitbedingung und abschließende Inspektion' \
        'Neben Unix-Zeit mit Modulus unterstützt der Prototyp UTC-Zeitfelder.' \
        'Zuerst wird eine Permit-Policy mit environment.utc.minute >= 0 geladen und der Zugriff geprüft. Danach kommt eine Deny-Policy mit environment.utc.hour >= 0 hinzu. Abschließend werden die aktivierten Policies und Attribute angezeigt.' \
        'Beide Bedingungen sind zu jeder gültigen Tageszeit wahr. Mit der Permit-Policy ist der Zugriff erlaubt. Bei gleichzeitig passenden Permit- und Deny-Policies hat Deny Vorrang und der Zugriff wird verweigert.' \
        'Die bewusst immer wahren Vergleiche zeigen die UTC-Felder unabhängig von der Uhrzeit der Vorführung. Das Admin-Tool zeigt die Policies, die Zugriffshilfe prüft deren tatsächliche Wirkung.'
    policy stream-permit permit '    environment.utc.minute >= 0;'
    access_is allow
    step 'Die zusätzliche UTC-Deny-Policy wird veröffentlicht. Sie hat Vorrang vor der passenden Permit-Policy.'
    policy utc deny '    environment.utc.hour >= 0;'
    explain 'Die zusätzliche UTC-Deny-Policy hat Vorrang vor der passenden Permit-Policy.'
    access_is deny
    admin

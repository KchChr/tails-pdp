#!/usr/bin/env bash
# Kapitel 4: Bei unveränderter Policy die Entscheidung allein über einen
# Systemattributwert ändern; Attribut- und Policygeneration sind getrennt.
# Wird in demo_worker eingebunden und nutzt dessen Runtime und Arbeitsbereich.

    chapter '4. Dynamisches Systemattribut' \
        'Das globale Attribut system.defcon steht auf 5. Diese Zahl dient als dynamischer Kontext der Zugriffsentscheidung.' \
        'Eine Deny-Policy mit system.defcon <= 2 wird geladen. Anschließend wird nur der Attributwert von 5 auf 2 und zurück auf 5 geändert.' \
        'Bei 5 ist die Deny-Bedingung falsch und der Zugriff erlaubt. Bei 2 ist sie erfüllt und der Zugriff verweigert. Nach der Rückkehr zu 5 ist er wieder erlaubt.' \
        'Die Policydatei bleibt während der Attributwechsel gleich. Im Log und im Admin-Tool ändert sich der Attributstand; die Runtime muss dafür nicht neu gestartet werden.'
    policy context deny '    system.defcon <= 2;'
    access_is allow
    step 'DEFCON sinkt auf 2: Die bereits geladene Deny-Policy trifft jetzt zu.'
    attribute system.attributes 'defcon = 2'
    access_is deny
    admin show-active
    step 'DEFCON steigt wieder auf 5: Dieselbe Policy trifft nicht mehr zu.'
    attribute system.attributes 'defcon = 5'
    access_is allow
    step 'Die Demo-Policy dieses Kapitels wird entfernt.'
    remove_policy context

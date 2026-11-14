#!/usr/bin/env bash
# Kapitel 6: Syntax-/Validierungsfehler dürfen keine neue Generation
# aktivieren. Nach der Ablehnung muss eine gültige Korrektur weiter möglich sein.
# Wird in demo_worker eingebunden und nutzt dessen Runtime und Arbeitsbereich.

    chapter '6. Ungültige Updates und anschließende Korrektur' \
        'DEFCON steht noch auf 2. Eine passende Deny-Policy wird geladen. Vor jedem fehlerhaften Update werden beide Generationsnummern gespeichert.' \
        'Zuerst wird eine Policy mit fehlendem Semikolon veröffentlicht. Nach ihrer Korrektur wird DEFCON=9 veröffentlicht, obwohl für dieses Attribut nur 1 bis 5 zulässig sind.' \
        'Beide fehlerhaften Updates werden verworfen. Die zuletzt gültigen Generationen und das wirksame Deny bleiben erhalten. Gültige Korrekturen werden anschließend wieder übernommen.' \
        'Rechts oben erscheint die Ablehnung. Links zeigt show-active die aktivierten Policies, Attribute und Generationen vor und nach jedem ungültigen Update sowie nach den gültigen Korrekturen. Ungültige Updates ändern keine Generation; erst die gültigen Korrekturen aktivieren einen neuen Stand. Der tatsächliche Zugriff wird zusätzlich geprüft.'
    policy robust deny '    system.defcon <= 2;'
    local before offset
    explain 'Aktiver Ausgangszustand vor der ungültigen Policy: Die Deny-Policy robust ist aktiviert und DEFCON steht auf 2.'
    admin show-active
    before="$(generations)"
    offset="$(wc -l < "$demo_root/runtime.log")"
    step 'Die nächste Policy ist absichtlich syntaktisch fehlerhaft. Sie darf nicht aktiviert werden.'
    printf 'policy "broken"\ndeny\n action == "file_open"\n' | publish "$policy_dir/broken.policy"
    wait_log 'POLICY sync failed' "$offset"
    [[ "$(generations)" == "$before" ]] || { fail 'Ungültige Policy änderte die Generation.'; return 1; }
    explain 'Aktiver Zustand nach der Ablehnung: broken wurde nicht aktiviert. Policies, Attribute und beide Generationen bleiben unverändert.'
    admin show-active
    observe "Ungültige Policy verworfen: Policygeneration ${before%% *} und Attributgeneration ${before##* } unverändert."
    access_is deny
    step 'Die fehlerhafte Datei wird durch eine gültige Permit-Policy ersetzt. Die bereits aktivierte Deny-Policy hat weiterhin Vorrang.'
    policy broken permit
    explain 'Nach der gültigen Policy-Korrektur ist broken zusätzlich aktiviert. Die Deny-Policy robust gilt weiterhin.'
    admin show-active
    access_is deny
    step 'Die korrigierte Policy broken wird entfernt. Danach wird der aktive Ausgangszustand für die Attributprüfung angezeigt.'
    remove_policy broken
    explain 'Aktiver Ausgangszustand vor dem ungültigen Attribut: broken wurde wieder entfernt. Die Deny-Policy robust und DEFCON=2 bleiben aktiv.'
    admin show-active
    before="$(generations)"
    offset="$(wc -l < "$demo_root/runtime.log")"
    step 'DEFCON=9 ist unzulässig. Der aktive Wert muss trotz geänderter Quelldatei bei 2 bleiben.'
    printf 'defcon = 9\n' | publish "$attribute_dir/system.attributes"
    wait_log 'Ignoring invalid stream attributes' "$offset"
    [[ "$(generations)" == "$before" ]] || { fail 'Ungültiges Attribut änderte die Generation.'; return 1; }
    explain 'Aktiver Zustand nach der Ablehnung von DEFCON=9: show-active zeigt weiterhin DEFCON=2 sowie dieselben Policies und Generationen.'
    admin show-active
    observe "Ungültiges Attribut verworfen: Policygeneration ${before%% *} und Attributgeneration ${before##* } unverändert."
    access_is deny
    step 'Mit dem gültigen Wert 5 wird ein neuer Attributstand aktiviert. Die Deny-Bedingung ist danach falsch und der Zugriff wieder erlaubt.'
    attribute system.attributes 'defcon = 5'
    explain 'Aktiver Zustand nach der gültigen Attribut-Korrektur: DEFCON=5 und die neue Attributgeneration sind sichtbar. Die Deny-Policy robust ist weiterhin aktiviert, ihre Bedingung ist jetzt jedoch falsch.'
    admin show-active
    access_is allow
    step 'Die Demo-Policy dieses Kapitels wird entfernt.'
    remove_policy robust

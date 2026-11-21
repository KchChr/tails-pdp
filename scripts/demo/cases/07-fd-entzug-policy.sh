#!/usr/bin/env bash
# Kapitel 7: file_open schützt neue Öffnungen. Der Userspace-PEP muss
# zusätzlich bestehende FDs selektiv entziehen, ohne den Prozess zu beenden.
# Wird in demo_worker eingebunden und nutzt dessen Runtime und Arbeitsbereich.

    chapter_start '7. Bereits geöffnete FDs durch eine neue Policy entziehen'

    #Seite 1
    chapter_section 'Ausgangslage' \
        'Bisher wurden neue Dateiöffnungen geprüft. Ein Prozess kann eine Datei bereits geöffnet haben, bevor eine neue Policy veröffentlicht wird.'
    chapter_section 'Aktion' \
        'Ein Beobachter mit drei offenen Filedescriptors (FD) zur geschützten Datei und zwei offenen FDs zur Kontrolldatei wird gestartet. Erst im nächsten Schritt wird eine passende Deny-Policy veröffentlicht.'
    chapter_section 'Erwartetes Verhalten' \
        'Zunächst müssen alle fünf FDs offen sein. Nach der Policyaktivierung führt der Userspace-PEP eine Re-evaluation für die bestehenden FDs aus. Das Enforcement entzieht ausschließlich die drei geschützten FDs.'
    printf '\n'
    pause_demo
    start_probe


    #Seite 2
    chapter_start '7a. FDs sind offen – jetzt Deny veröffentlichen'
    chapter_section 'Ausgangslage' \
        'Der Beobachter hält alle fünf FDs offen. Vor der Änderung wird zusätzlich geprüft, dass diese FDs noch auf die erwarteten Dateien verweisen.'
    chapter_section 'Aktion' \
        'Mit Enter wird eine Deny-Policy für die geschützte Ressource veröffentlicht. Die Policyaktivierung löst eine Re-evaluation der bestehenden FDs aus. Ein zusätzlicher Kommando-Filter wird in diesem Kapitel nicht verwendet.'
    chapter_section 'Erwartetes Verhalten' \
        'Die drei geschützten FDs wechseln auf geschlossen. Beide Kontroll-FDs bleiben offen; der Prozess wird nicht beendet.'
    printf '\n'
    pause_demo
    assert_probe_identity
    policy revoke deny ''
    expect_revoked


    #Seite 3
    step 'Der selektive Entzug ist bestätigt. Der Beobachter wird jetzt gezielt beendet und die Demo-Policy für das nächste Kapitel entfernt.'
    stop_probe
    remove_policy revoke

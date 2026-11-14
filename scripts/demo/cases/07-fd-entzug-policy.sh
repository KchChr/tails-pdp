#!/usr/bin/env bash
# Kapitel 7: file_open schützt neue Öffnungen. Der Userspace-PEP muss
# zusätzlich bestehende FDs selektiv entziehen, ohne den Prozess zu beenden.
# Wird in demo_worker eingebunden und nutzt dessen Runtime und Arbeitsbereich.

    chapter '7. Bereits geöffnete FDs durch eine neue Policy entziehen' \
        'Bisher wurden neue Dateiöffnungen geprüft. Ein Prozess kann eine Datei aber schon geöffnet haben, bevor eine neue Policy veröffentlicht wird.' \
        'Ein Beobachter mit drei offenen FDs zur geschützten Datei und zwei offenen FDs zur Kontrolldatei wird gestartet. Erst im nächsten Schritt wird eine passende Deny-Policy veröffentlicht.' \
        'Zunächst müssen alle fünf FDs offen sein. Nach der Policyaktivierung prüft der Userspace-PEP bestehende FDs erneut und entzieht ausschließlich die drei geschützten.' \
        'FD bedeutet Dateideskriptor: eine offene Dateireferenz in einem Prozess. Rechts unten zeigt True einen offenen FD und False einen geschlossenen. Der Beobachterprozess soll weiterlaufen.'
    start_probe
    chapter '7a. FDs sind offen – jetzt Deny veröffentlichen' \
        'Der Beobachter hält alle fünf FDs offen. Vor der Änderung wird zusätzlich geprüft, dass diese FDs noch auf die erwarteten Dateien verweisen.' \
        'Mit Enter wird eine Deny-Policy für die geschützte Datei und das Kommando tails-demo-fd veröffentlicht. Die Policyaktivierung löst eine erneute FD-Prüfung aus.' \
        'Die drei geschützten FDs wechseln auf False. Beide Kontroll-FDs bleiben True; der Prozess wird nicht beendet.' \
        'Rechts oben ist die Policyaktivierung mit anschließendem Scan sichtbar. Rechts unten ist der tatsächliche FD-Zustand zu sehen. Ein Logeintrag allein genügt nicht als Nachweis.'
    assert_probe_identity
    policy revoke deny '' tails-demo-fd
    expect_revoked
    step 'Der selektive Entzug ist bestätigt. Der Beobachter wird jetzt gezielt beendet und die Demo-Policy für das nächste Kapitel entfernt.'
    stop_probe
    remove_policy revoke

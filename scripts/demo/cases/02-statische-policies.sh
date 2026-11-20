#!/usr/bin/env bash
# Kapitel 2: Echte Programme und Benutzeridentitäten variieren jeweils einen Filter.
# Vor der Policy werden beide Benutzer geprüft, damit normale Dateirechte den Vergleich nicht verfälschen.
# Der Hardlink belegt zusätzlich den Abgleich über Gerät und Inode.

    chapter_start '2. Statische Policies: Kommando, Benutzer und Ressource'
    chapter_section 'Ausgangslage' \
        "Die Dateien sind zunächst zugänglich:
  Ressource: $target
  Kontrolldatei: $safe
  Hardlink auf die Ressource: ${target%/*}/alias.txt"
    chapter_section 'Aktion' \
        'Eine Deny-Policy wird veröffentlicht. Danach werden subject.uid, command und resouce einzeln variiert.'

    chapter_section 'Erwartetes Verhalten' \
        'Deny bei Übereinstimmung aller Attribute, ansonsten Permit'
    chapter_section 'Beobachtung' \
        'echo $UID zeigt die UID des Demo-Workers. sudo -u wechselt die UID ; id -u zeigt dessen tatsächliche UID. Dabei ändern sich Real-UID und effektive UID. Vor der Policy muss cat für beide Benutzer funktionieren, damit eine spätere Verweigerung dem Prototyp zugeordnet werden kann. cat und head werden tatsächlich ausgeführt.'
    printf '\n'
    pause_demo
    explain 'Vor der Policy liest der Demo-Worker die geschützte Datei mit cat.'
    command_access_is allow cat -
    step 'Auch der Vergleichsbenutzer muss die Datei ohne Policy lesen können. Eine Verweigerung hier zeigt ein Problem mit den normalen Dateirechten.'
    command_access_is allow cat "$comparison_uid"
    step 'Die Deny-Policy für die UID "$UID", command == "cat"; und die geschützte Ressource wird veröffentlicht.'
    policy scoped deny "    subject.uid == $UID;" cat
    command_access_is deny cat -
    step 'Nur der Benutzer wird geändert: sudo -u startet cat mit der anderen Benutzeridentität.'
    command_access_is allow cat "$comparison_uid"
    step 'Nur command ändert sich zu command == "head";. Die UID des Demo-Workers bleibt gleich.'
    command_access_is allow head -
    step 'cat liest als Demo-Worker die separate Kontrolldatei. Dieser Zugriff muss erlaubt bleiben.'
    command_access_is allow cat - "$safe"
    step 'Der alternative Hardlink-Pfad bezeichnet dieselbe geschützte Datei. cat muss auch über diesen Pfad abgewiesen werden.'
    command_access_is deny cat - "$PROJECT_ROOT/demo/files/alias.txt"
    admin show-active
    step 'Die Policy wird entfernt. Derselbe zuvor verweigerte Zugriff muss wieder möglich sein.'
    remove_policy scoped
    command_access_is allow cat -

#!/usr/bin/env bash
# Kapitel 2: Pro Negativkontrolle genau einen Filter verändern. Der Hardlink
# belegt zusätzlich, dass die Ressourcenidentität und nicht der Pfad zählt.
# Wird in demo_worker eingebunden und nutzt dessen Runtime und Arbeitsbereich.

    chapter_start '2. Statische Policies: Kommando, Benutzer und Ressource'
    chapter_section 'Ausgangslage' \
        "Die Dateien sind zunächst zugänglich:
  Ressource: $target
  Kontrolldatei: $safe
  Hardlink wird auf die ressource gesetzt: ${target%/*}/alias.txt"
    chapter_section 'Aktion' \
        'Eine Deny-Policy wird für genau drei gemeinsam erforderliche Merkmale veröffentlicht: `subject.uid == 60001;`, `command == "cat";` und die geschützte resource.path. Die Real-UID wird durch subject.uid dargestellt. Danach werden diese Merkmale einzeln variiert.'
    chapter_section 'Erwartetes Verhalten' \
        'Der Zugriff mit `subject.uid == 60001;` und `command == "cat";` auf die geschützte Ressource wird verweigert. Eine andere UID, ein anderes Kommando und der Zugriff auf die Kontrolldatei bleiben erlaubt. Der Zugriff über den Hardlink wird ebenfalls verweigert, weil Gerät und Inode mit der geschützten Datei übereinstimmen.'
    chapter_section 'Beobachtung' \
        'Hier werden die Programme cat und head tatsächlich gestartet. setpriv setzt nur die Real-UID des jeweiligen Prozesses auf 60001 oder 60002; dafür sind keine zusätzlichen Benutzerkonten nötig. Die effektive UID bleibt root, damit gewöhnliche Dateirechte den Vergleich nicht beeinflussen. Der Kommando-Filter prüft den unter Linux geführten Kommandonamen comm: `command == "cat";` passt zur Policy, `command == "head";` nicht. Erlaubte Aufrufe zeigen den Dateiinhalt; beim verweigerten cat-Aufruf erscheint dessen echte Fehlermeldung.'
    printf '\n'
    pause_demo
    explain 'Vor dem Laden der Policy ist die Dateiöffnung mit `command == "cat";` und `subject.uid == 60001;` erlaubt.'
    command_access_is allow cat 60001
    step 'Die Deny-Policy mit `command == "cat";`, `subject.uid == 60001;` und der geschützten resource.path wird veröffentlicht und anschließend geprüft.'
    policy scoped deny '    subject.uid == 60001;' cat
    explain 'Alle drei Filter passen: Die Dateiöffnung muss verweigert werden.'
    command_access_is deny cat 60001
    step 'Nur subject.uid ändert sich: `subject.uid == 60002;`. Mit `command == "cat";` muss die Dateiöffnung weiterhin erlaubt sein.'
    command_access_is allow cat 60002
    step 'Nur command ändert sich: `command == "head";`. Mit `subject.uid == 60001;` muss die Dateiöffnung weiterhin erlaubt sein.'
    command_access_is allow head 60001
    step 'Mit `command == "cat";` und `subject.uid == 60001;` wird jetzt die Kontrolldatei geöffnet. Dieser Zugriff muss erlaubt bleiben.'
    command_access_is allow cat 60001 "$safe"
    step 'Der alternative Hardlink-Pfad bezeichnet dieselbe geschützte Datei. cat muss auch über diesen Pfad abgewiesen werden.'
    command_access_is deny cat 60001 "$PROJECT_ROOT/demo/files/alias.txt"
    admin show-active
    step 'Die Policy wird entfernt. Derselbe zuvor verweigerte Zugriff muss wieder möglich sein.'
    remove_policy scoped
    command_access_is allow cat 60001

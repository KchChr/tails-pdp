#!/usr/bin/env bash
# Kapitel 2: Pro Negativkontrolle genau einen Filter verändern. Der Hardlink
# belegt zusätzlich, dass die Ressourcenidentität und nicht der Pfad zählt.
# Wird in demo_worker eingebunden und nutzt dessen Runtime und Arbeitsbereich.

    chapter '2. Statische Policies: Kommando, Benutzer und Ressource' \
        "Die Dateien sind zunächst zugänglich:
  Geschützte Datei: demo/files/protected.txt
  Kontrolldatei: demo/files/control.txt
  Hardlink auf die geschützte Datei: demo/files/alias.txt
  protected.txt und alias.txt bezeichnen dieselbe Datei; control.txt ist eine separate Datei." \
        'Eine Deny-Policy wird für genau drei gemeinsam erforderliche Merkmale veröffentlicht: Real-UID 60001, Kommando cat und die geschützte Ressource. Danach werden diese Merkmale einzeln variiert.' \
        'Nur die passende Kombination auf protected.txt wird verweigert. Eine andere UID, ein anderes Kommando und die separate control.txt bleiben erlaubt. alias.txt wird ebenfalls verweigert, weil Gerät und Inode mit protected.txt übereinstimmen.' \
        'Hier werden die Programme cat und head tatsächlich gestartet. setpriv setzt nur die Real-UID des jeweiligen Prozesses auf 60001 oder 60002; dafür sind keine zusätzlichen Benutzerkonten nötig. Die effektive UID bleibt root, damit gewöhnliche Dateirechte den Vergleich nicht beeinflussen. Der Kommando-Filter prüft den unter Linux geführten Kommandonamen comm: cat passt zur Policy, head nicht. Erlaubte Aufrufe zeigen den Dateiinhalt; beim verweigerten cat-Aufruf erscheint dessen echte Fehlermeldung.'
    explain 'Vor dem Laden der Policy kann cat mit Real-UID 60001 die geschützte Datei lesen.'
    command_access_is allow cat 60001
    step 'Die Deny-Policy für cat, Real-UID 60001 und die geschützte Datei wird veröffentlicht und anschließend geprüft.'
    policy scoped deny '    subject.uid == 60001;' cat
    explain 'Alle drei Filter passen: Die Dateiöffnung muss verweigert werden.'
    command_access_is deny cat 60001
    step 'Nur die Real-UID wird auf 60002 geändert. cat muss die geschützte Datei weiterhin lesen können.'
    command_access_is allow cat 60002
    step 'Nur das Kommando wird geändert: head muss die geschützte Datei mit Real-UID 60001 lesen können.'
    command_access_is allow head 60001
    step 'cat mit Real-UID 60001 liest jetzt die separate Kontrolldatei. Dieser Zugriff muss erlaubt bleiben.'
    command_access_is allow cat 60001 "$safe"
    step 'Der alternative Hardlink-Pfad bezeichnet dieselbe geschützte Datei. cat muss auch über diesen Pfad abgewiesen werden.'
    command_access_is deny cat 60001 "$PROJECT_ROOT/demo/files/alias.txt"
    admin show-active
    step 'Die Policy wird entfernt. Derselbe zuvor verweigerte Zugriff muss wieder möglich sein.'
    remove_policy scoped
    command_access_is allow cat 60001

#!/usr/bin/env bash
# Kapitel 7: Ein Bash-Prozess hält fünf FDs offen. Vorher/nachher zeigen
# /proc und PEP-Logs den selektiven Entzug bei unveränderter Prozessidentität.
# Wird in demo_worker eingebunden und nutzt dessen Runtime und Arbeitsbereich.

    chapter_start '7. Bereits geöffnete FDs durch eine neue Policy entziehen'

    #Seite 1
    chapter_section 'Ausgangslage' \
        'Bisher wurde eine Datei jeweils neu geöffnet. Jetzt soll eine Policy auch auf Dateien wirken, die ein laufender Prozess bereits geöffnet hat.'
    chapter_section 'Aktion' \
        "Wir starten einen Bash-Prozess, der die Dateien offen hält:

  FD 10, 11, 12: $target
  FD 13, 14:     $safe

Ein Dateideskriptor (FD) ist eine Nummer für eine geöffnete Datei innerhalb eines Prozesses.
exec 10<\"$target\" öffnet die Datei zum Lesen und hält sie als FD 10 in dieser Bash offen.
Der Prozess schließt diese fünf FDs während der Vorführung nicht selbst und öffnet sie nach einem Entzug nicht erneut."
    chapter_section 'Erwartetes Verhalten' \
        'Zunächst sind alle fünf FDs offen. Rechts unten zeigt ls -l /proc/<PID>/fd, auf welche Dateien die Nummern verweisen. Die PID bezeichnet den Bash-Prozess. Vor der Policy-Veröffentlichung bleibt Zeit, diese Ausgangslage anzusehen.'
    printf '\n'
    pause_demo
    start_probe --native
    explain "Der Bash-Prozess läuft mit PID $probe_pid. Seine offenen Dateien:"
    run_cmd "ls -l /proc/$probe_pid/fd"
    explain 'Die Einträge 10, 11 und 12 zeigen auf die geschützte Datei; 13 und 14 auf die Kontrolldatei. Mit Enter folgt die Policy-Veröffentlichung.'


    #Seite 2
    chapter_start '7a. Derselbe Prozess – jetzt Deny veröffentlichen'
    chapter_section 'Ausgangslage' \
        "Der Bash-Prozess mit PID $probe_pid hält die Dateien weiterhin offen. Er wird weder beendet noch neu gestartet."
    chapter_section 'Aktion' \
        'Mit Enter veröffentlichen wir eine Deny-Policy für die geschützte Datei. Der Userspace-PEP prüft daraufhin die bereits offenen FDs erneut.'
    chapter_section 'Erwartetes Verhalten' \
        'Rechts oben protokolliert der Userspace-PEP das Schließen von FD 10, 11 und 12. Rechts unten verschwinden diese Einträge aus /proc. FD 13 und 14 bleiben offen. Die PID bleibt gleich: Das Enforcement betrifft die geschützte Datei, während derselbe Prozess weiterläuft.'
    printf '\n'
    pause_demo
    assert_probe_identity
    local revoke_offset
    revoke_offset="$(wc -l < "$demo_root/runtime.log")"
    policy revoke deny ''
    expect_revoked --native
    # Der Entzug muss sowohl in /proc als auch im tatsächlichen PEP-Log belegt sein.
    local revoked_fd
    for revoked_fd in 10 11 12; do
        wait_log "USERSPACE_PEP closed pid=$probe_pid fd=$revoked_fd " "$revoke_offset"
    done
    explain "Derselbe Bash-Prozess mit PID $probe_pid nach dem Enforcement:"
    run_cmd "ls -l /proc/$probe_pid/fd"
    explain 'FD 10, 11 und 12 fehlen. Die Kontroll-FDs 13 und 14 sind weiterhin vorhanden; der Bash-Prozess läuft weiter.'


    #Seite 3
    step 'Der Vergleich ist abgeschlossen. Jetzt beenden wir den Bash-Prozess und entfernen die Policy für das nächste Kapitel.'
    stop_probe
    remove_policy revoke

#!/usr/bin/env bash
# Einführung: Zweck, Bedienung, Bildschirmaufteilung und absolute Arbeitsverzeichnisse.
# Wird im gemeinsamen Demo-Worker ausgeführt; startet noch keine Runtime.

    printf '\n%sPrototyp – geführte Live-Demo%s\n\n' "$color_heading" "$color_reset"
    printf 'Die Demo zeigt, wie Policies, Attribute und Zeitbedingungen den\n'
    printf 'Dateizugriff steuern und bereits geöffnete Dateideskriptoren entzogen werden.\n'

    printf '\n%sBedienung%s\n' "$color_section" "$color_reset"
    printf '  Enter: nächster Schritt.\n'
    printf '  Strg+C: Beenden.\n'

    printf '\n%sAnzeige%s\n' "$color_section" "$color_reset"
    printf '  Links:         Demo\n'
    printf '  Rechts oben:   Logs\n'
    printf '  Rechts unten:  Filedesciptors\n'

    printf '\n%srelevante Dateien und Ordner%s\n' "$color_section" "$color_reset"
    printf '  Policies:  %s\n  Attribute: %s\n  Dateien:   %s\n' "$policy_dir" "$attribute_dir" "${target%/*}"
    printf '  Logs: %s\n\n' "$demo_root"
    pause_demo 'Enter: erstes Kapitel anzeigen | Strg+C: abbrechen '

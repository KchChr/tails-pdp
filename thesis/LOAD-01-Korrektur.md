# Korrektur des Attributkapazitätsfehlers aus LOAD-01

## Verhalten und Umsetzung

Commit `35e1d2b` korrigiert den zuvor nachgewiesenen Runtime-Abbruch bei einem
Attributupdate, das die gemeinsame Kapazität beider Attributbanken überschreitet.
Die Map wird nicht vergrößert und es wird keine feste Grenze von 512 Attributen
pro Generation eingeführt.

`commit_attributes` liest zunächst die aktive Generation, dann die tatsächliche
Kapazität der gepinnten Map und die Anzahl der Einträge außerhalb der zu
ersetzenden Bank. Vor jeder Lösch- oder Schreiboperation muss gelten:

```text
verbleibende Einträge + neue Attribute <= tatsächliche Map-Kapazität
```

Die Einträge der inaktiven Bank werden dabei nicht doppelt gezählt. Bei einem
Lesefehler der Generationsnummer wird kein Ersatzwert verwendet und keine Bank
verändert. Eine fehlgeschlagene Belegungs-/Kapazitätsabfrage bricht ebenfalls vor
den Schreiboperationen ab.

Im laufenden Updater werden Commitfehler protokolliert und abgefangen. Die aktive
Generation und `last_applied` bleiben unverändert; kein Enforcement-Trigger wird
gesendet. Auch ein unerwarteter Fehler mitten im Schreiben oder bei der
Aktivierung beendet den Updater nicht. Ein späteres Dateiereignis kann erneut
versuchen, die Daten zu übernehmen; dabei wird die inaktive Bank zunächst wieder
bereinigt. Es gibt keinen neuen periodischen Retry- oder Scan-Timer.

Die initiale Einrichtung verwendet weiterhin den direkt fehlerliefernden
Commitpfad. Fehler beim ersten Laden verhindern damit den Start. Ebenso bleibt
ein geschlossener Enforcement-Kanal nach erfolgreicher Aktivierung ein Fehler;
er wird nicht als fehlgeschlagenes Attributupdate verschluckt. Die Fehlerbehandlung
des Dateiwatchers und das zentrale `tokio::select!` wurden nicht verändert.

## Regressionstests

Sieben neue Rust-Tests ergänzen die bestehenden Tests im Attributloader:

| Test | Nachweis |
|---|---|
| `capacity_rejection_happens_before_any_map_mutation` | Zu große Generation wird vor jedem Löschen/Schreiben abgelehnt; beide Banken bleiben unverändert |
| `capacity_accounts_for_retained_entries_not_a_fixed_half_map_limit` | Größere als halbe Map-Belegung ist bei kleiner aktiver Bank möglich; alte Zielbank wird nicht doppelt gezählt |
| `generation_and_occupancy_read_errors_never_modify_either_bank` | Lesefehler führen zu keiner Bankänderung |
| `update_commit_errors_preserve_state_and_allow_a_later_successful_update` | Lösch-, Teil-Schreib- und Aktivierungsfehler werden im Updatepfad abgefangen, senden keinen Trigger und erlauben ein späteres erfolgreiches Update |
| `update_capacity_and_generation_read_errors_send_no_trigger_and_recover` | Auch Kapazitäts- und Generationslesefehler erhalten den letzten Stand und erlauben eine Korrektur |
| `closed_enforcement_channel_remains_fatal_after_successful_activation` | Benachrichtigungsfehler bleiben sichtbar und beenden den Updatepfad |
| `initial_commit_failure_is_still_reported_to_the_caller` | Fehler bei der initialen Commitoperation werden weiterhin weitergereicht |

LOAD-01 verwendet weiterhin echte Maps und eine unveränderte Kapazität von 1024.
Nach drei gültigen 512-Attributständen aktiviert der Test eine Deny-Policy auf
`system.field0 == 3`. Das zu große Update mit 513 Attributen und `field0 = 4`
muss abgelehnt werden. Der Test vergleicht Generationen sowie die gesamte aktive
Attributausgabe und prüft weiterhin wirksames Deny. Anschließend folgen gültige
512-Attributstände mit `field0 = 4` und `field0 = 3`: Allow und danach wieder Deny
müssen ohne Runtime-Neustart wirksam werden.

## Ergebnis auf nixrun

Getesteter Code: `35e1d2b`, Linux 6.16.12, x86_64. Der Transfer erfolgte wie
vereinbart per lokalem Commit/Push und anschließendem Fast-forward-Pull auf nixrun.

| Prüfung | Ergebnis |
|---|---|
| Rust-Formatierung | Bestanden |
| Rust-Unit-/Komponententests | 59 bestanden, keine fehlgeschlagen |
| Clippy des Attributloaders, alle Targets, `-D warnings` | Bestanden |
| Release-Build von Runtime und Admintool einschließlich eBPF | Bestanden |
| LOAD-01 | Bestanden: kontrollierte Ablehnung, unveränderte aktive Werte und erfolgreiche Folgeupdates |
| STAB-01 | Bestanden: 100 Zyklen in 178 Sekunden |
| E2E-01 bis E2E-17 | Alle 17 bestanden |
| Gesamte Prüfkette `./test.sh` | Weiterhin Abbruch am unabhängigen bestehenden Clippy-Befund `items_after_test_module` in `tails-pdp-userspace-common` |

Im Lasttest blieben Policygeneration 34 und Attributgeneration 4 nach der
Kapazitätsablehnung unverändert. Die gesicherten Attributausgaben vor und nach der
Ablehnung sind identisch. Das gültige Folgeupdate aktivierte Attributgeneration 5;
der anschließende Deny–Allow–Deny-Nachweis gelang ohne Neustart. Die Kernelprüfungen
der ergänzenden Testläufe meldeten keine der vom Runner erkannten Kernel-Faults.

Nachweise:

- [Rust-Tests und bestehender Clippy-Befund](test-results/2026-09-10/attribute-fix/rust-tests-and-clippy.log)
- [Separates Clippy und Release-Build](test-results/2026-09-10/attribute-fix/build-and-crate-clippy.log)
- [LOAD-01 und STAB-01: JSON-Bericht](test-results/2026-09-10/attribute-fix/load-and-stability.json)
- [LOAD-01 und STAB-01: vollständige Artefakte](test-results/2026-09-10/attribute-fix/load-and-stability-artifacts.tar.gz)
- [Alle 17 E2E-Tests: Ablaufprotokoll](test-results/2026-09-10/attribute-fix/e2e.log)
- [E2E-11 bis E2E-17: zusätzliche Artefakte](test-results/2026-09-10/attribute-fix/e2e-artifacts.tar.gz)

Die zuvor archivierten Fehler- und Performanceergebnisse wurden nicht überschrieben.
Der neue Lauf prüft die Produktkorrektur und ihre Regressionen; er ersetzt keine
Performance-Neuvermessung und liefert keinen allgemeinen Langzeit- oder
Nebenläufigkeitsnachweis.

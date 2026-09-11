# Übersicht der implementierten und geplanten Tests

## 1. Zweck und Abgrenzung

Dieses Dokument erfasst die im Repository aktuell implementierten Tests und
Qualitätsprüfungen. Die Übersicht beruht auf dem Quellstand vom 10. September 2026.
Sie beschreibt, **was implementiert ist** und welche zusätzlichen Tests noch sinnvoll
wären. Der Implementierungsstatus sagt nicht aus, ob ein konkreter Testlauf auf dem
Zielsystem erfolgreich war. Die Ergebnisse eines ausgeführten Testlaufs müssen für
die Evaluation gesondert protokolliert werden.

Für die Tabellen gelten zwei Statuswerte:

- **Implementiert:** Der automatisierte Test beziehungsweise Prüfschritt ist im
  Repository vorhanden.
- **TODO:** Der Test ist fachlich sinnvoll, aber noch nicht automatisiert
  implementiert.

Der Status **Implementiert** ist somit kein Testergebnis. Ein Test gilt in Kapitel 6
erst dann als bestanden, wenn er auf der dokumentierten Zielumgebung ausgeführt
wurde und das festgelegte Beobachtungskriterium erfüllt ist.

Der Testbestand ist in drei Ebenen gegliedert:

1. **Unit- und Komponententests** prüfen isolierte Logik in Rust, teilweise mit
   Testdoubles statt realer BPF-Maps oder eines realen FD-Entzugs.
2. **Privilegierte End-to-End-Tests** starten die vollständige Runtime auf einem
   Linux-Zielsystem und prüfen den echten eBPF-LSM-Hook sowie den Userspace-PEP.
3. **Statische Qualitäts- und Build-Prüfungen** prüfen Formatierung, Lints und
   Übersetzbarkeit. Sie sind keine funktionalen Laufzeittests im engeren Sinn.

Aktuell sind **59 Rust-Tests** in sieben Testmodulen sowie **25 privilegierte
Szenarien** vorhanden. `./test.sh` ist der zentrale Einstiegspunkt für sämtliche Prüfungen und
fordert für die Systemtests selbst über `sudo` Root-Rechte an. `test-e2e.sh` führt E2E-01 bis
E2E-17 aus, mit einer Bashdatei je ID unter
`tests/e2e/`. `test-evaluation.sh` führt die 15 ergänzten Szenarien aus
(einschließlich E2E-11 bis E2E-17; diese werden bei der Gesamtzahl nur einmal
gezählt). Weitere IDs liegen unter `tests/evaluation/` ebenfalls als Bashdatei.
Nur ptrace-Koordination und präzise Messungen verwenden je eine Pythondatei
hinter einem Bash-Wrapper; FD- und UID-Systemaufrufe verwenden kleine Helfer. Die zuvor offenen
**18 Testvorschläge sind implementiert**: COMP-01 bis COMP-03 als Rust-Tests,
die übrigen als privilegierte Tests beziehungsweise Messungen.

Ausgeführte Ergebnisse, Bewertung des bisherigen Bestands und nachgewiesene
Produktgrenzen stehen in [Testbewertung.md](Testbewertung.md). Ein implementierter
Test kann fehlschlagen. Der früher in LOAD-01 nachgewiesene Runtime-Abbruch wurde
nach gesondertem Auftrag korrigiert; Umsetzung und neue Nachweise stehen in
[LOAD-01-Korrektur.md](LOAD-01-Korrektur.md). Die alten Ergebnisse bleiben als
historischer Stand erhalten.

## 2. Übersicht nach Testart

| Testart | Ausführung | Anzahl | Benötigt Root? | Hauptzweck | Status |
|---|---|---:|---:|---|---|
| Unit- und Komponententests | `./test.sh` bzw. `cargo test` | 59 | nein | Isolierte Prüfung von Policylogik, Parsern, Generationen und Userspace-PEP | Implementiert |
| End-to-End- und Evaluationsszenarien | Bestandteil von `./test.sh`; Teilrunner separat aufrufbar | 25 Szenarien | ja | Reales Laden, Anhängen und Durchsetzen sowie Performance, Last und Stabilität | Implementiert |
| Formatprüfung | Teil von `./test.sh` | 1 Prüfschritt | nein | Einheitliche Rust-Formatierung | Implementiert |
| Clippy | Teil von `./test.sh` | 1 Prüfschritt | nein | Statische Analyse mit Warnungen als Fehler | Implementiert |
| Release-Build | Teil von `./test.sh` | 1 Prüfschritt | nein | Übersetzung der Userspace-Binaries und des eingebetteten eBPF-Objekts | Implementiert |

## 3. Unit- und Komponententests

### 3.1 Gemeinsame Policy- und Entscheidungslogik

**Datei:** `tails-pdp-common/src/lib.rs`  
**Anzahl:** 16 Tests  
**Art:** Unit-Tests

Die Funktionen dieses Crates werden teilweise sowohl vom Kernelspace- als auch vom
Userspace-Pfad verwendet. Die Tests prüfen die gemeinsame Daten- und
Entscheidungssemantik ohne einen geladenen LSM-Hook.

| Testfunktion | Geprüftes Verhalten | Status |
|---|---|---|
| `policy_time_derives_utc_components_from_unix_seconds` | Ableitung von Stunde, Minute und Sekunde aus einem Unix-Zeitstempel sowie Tageswechsel | Implementiert |
| `decision_state_uses_deny_overrides` | Combining-Regel: keine Entscheidung und Permit erlauben; ein Deny überstimmt Permit | Implementiert |
| `file_open_static_policy_matches_all_request_fields` | Matching einer statischen Datei-Policy anhand von UID, Kommando, Device und Inode; Nicht-Matches werden abgewiesen | Implementiert |
| `any_subject_static_policy_matches_every_uid` | `ANY_SUBJECT` passt auf unterschiedliche UIDs | Implementiert |
| `utc_component_policies_respect_operator_boundaries` | Vergleichsoperatoren an Grenzwerten einer UTC-Stundenbedingung | Implementiert |
| `attribute_conditions_match_numbers_and_booleans` | Vergleiche dynamischer Zahlen- und Boolean-Attribute | Implementiert |
| `attribute_conditions_match_string_hashes_only_by_equality` | Stringattribute werden über Hashwerte und ausschließlich mit Gleichheit verglichen | Implementiert |
| `attribute_conditions_reject_type_mismatches` | Unterschiedliche Attributtypen führen zu keinem Match | Implementiert |
| `attribute_object_ids_are_namespace_scoped` | Objektidentifikatoren unterscheiden System-, Subject- und Resource-Namespace | Implementiert |
| `stream_policy_with_dynamic_attributes_requires_map_lookup` | Eine Policy mit dynamischem Attribut kann ohne Attribut-Lookup nicht abschließend ausgewertet werden | Implementiert |
| `stream_policy_returns_entitlement_when_condition_matches` | Eine passende zeitabhängige Bedingung liefert das Policy-Entitlement | Implementiert |
| `stream_policy_uses_utc_hour_from_shared_policy_time` | Stream-Policy verwendet die Stunde aus der gemeinsamen Zeitrepräsentation | Implementiert |
| `stream_policy_is_not_applicable_when_condition_does_not_match` | Eine nicht erfüllte Stream-Bedingung macht die Policy nicht anwendbar | Implementiert |
| `stream_policy_with_zero_modulo_is_not_applicable` | Defensives Verhalten bei einem Modulo-Wert von null | Implementiert |
| `file_open_stream_policy_respects_command_filter` | Kommando-Filter einer zeitabhängigen `file_open`-Policy | Implementiert |
| `socket_bind_stream_policy_respects_command_filter` | Kommando-Filter der vorhandenen gemeinsamen `socket_bind`-Policylogik | Implementiert |

**Aussagekraft:** Die Tests belegen die isolierte Policysemantik. Sie belegen nicht,
dass der Kernel-Verifier das eBPF-Programm akzeptiert, dass BPF-Maps korrekt gelesen
werden oder dass der LSM-Hook eine reale Dateiöffnung verhindert.

### 3.2 Einlesen, Parsen und Aktivieren von Policies

**Datei:** `tails-pdp-policy-loader/src/policy_source.rs`  
**Anzahl:** 14 Tests  
**Art:** Unit- und Komponententests; Generationstests mit `FakePolicyStore`

| Testfunktion | Geprüftes Verhalten | Status |
|---|---|---|
| `translates_dynamic_subject_attribute` | Übersetzung eines frei benannten Subject-Attributs in die interne Stream-Policy-Repräsentation | Implementiert |
| `rejects_unsupported_attribute_name` | Ablehnung eines Attributnamens mit nicht unterstützten Zeichen | Implementiert |
| `translates_static_and_time_policies` | Gemeinsame Übersetzung einer statischen und einer zeitabhängigen Datei-Policy | Implementiert |
| `rejects_duplicate_policy_names` | Ablehnung doppelter Policynamen | Implementiert |
| `rejects_missing_semicolon_and_unknown_action` | Ablehnung eines fehlenden Semikolons und einer nicht unterstützten Action | Implementiert |
| `rejects_disabled_socket_bind_action` | Explizite Ablehnung der derzeit deaktivierten `socket_bind`-Action | Implementiert |
| `rejects_too_many_dynamic_conditions_and_policies` | Durchsetzung der Grenzen für dynamische Bedingungen und Policies pro Bank | Implementiert |
| `rejects_invalid_time_ranges_and_zero_modulo` | Ablehnung ungültiger UTC-Werte und eines Modulo-Werts von null | Implementiert |
| `reads_only_policy_files_recursively` | Rekursives Einlesen ausschließlich von Dateien mit der Endung `.policy` | Implementiert |
| `generation_is_activated_only_after_bank_write` | Neue Generation wird erst nach dem Schreiben der inaktiven Bank aktiviert | Implementiert |
| `failed_bank_write_keeps_previous_generation_active` | Ein Schreibfehler verändert die aktive Generation nicht | Implementiert |
| `failed_activation_does_not_report_new_generation` | Ein Aktivierungsfehler wird nicht als erfolgreiche neue Generation gemeldet | Implementiert |
| `unchanged_and_repeatedly_failed_documents_are_not_retried` | Unveränderte sowie bereits fehlgeschlagene Dokumentstände werden nicht erneut synchronisiert | Implementiert |
| `preparing_bank_disables_entries_after_last_policy` | Freie Einträge einer vorbereiteten Policybank werden deaktiviert, sodass alte Policies nicht bestehen bleiben | Implementiert |

**Aussagekraft:** Parser, Übersetzung und Reihenfolge eines Generationenwechsels
werden isoliert geprüft. Die Generationstests verwenden keine realen BPF-Maps; die
Aktivierung auf echten gepinnten Maps wird ergänzend durch den End-to-End-Test
abgedeckt.

### 3.3 Verarbeitung dynamischer Attributdateien

**Datei:** `tails-pdp-attribute-loader/src/stream_attributes.rs`  
**Anzahl:** 13 Tests (einschließlich `src/evaluation_tests.rs`)
**Art:** Unit- und Komponententests

| Testfunktion | Geprüftes Verhalten | Status |
|---|---|---|
| `parses_supported_attribute_values` | Parsen von Zahlen, Boolean-Werten und gehashten Stringwerten | Implementiert |
| `validates_attribute_names_and_defcon_range` | Zulässige und unzulässige Attributnamen sowie Wertebereich von `system.defcon` | Implementiert |

**Ergänzungen in `src/evaluation_tests.rs`:**

| Testfunktion | Geprüftes Verhalten | Status |
|---|---|---|
| `comp01_reads_namespaces_resource_identity_and_ignores_other_extensions` | Vollständiges Verzeichnis mit drei Namespaces, rekursiver Ressourcenauflösung und ignorierten Dateiendungen | Implementiert |
| `comp01_rejects_invalid_recognized_files_and_duplicate_attributes` | Ungültige UID-Dateinamen, doppelte Attribute, DEFCON-Bereich und fehlende Ressource | Implementiert |
| `comp02_clear_partial_write_and_activation_errors_preserve_visible_generation` | Simulierte Lösch-, Teil-Schreib- und Aktivierungsfehler erhalten die aktive Bank | Implementiert |
| `comp02_activation_follows_complete_write_and_clears_stale_entries` | Reihenfolge, Bankbereinigung, leere Generation und Generationenüberlauf | Implementiert |

**Aussagekraft:** Parser und Commitsteuerung werden mit echten Dateien beziehungsweise
einem austauschbaren Speicher geprüft. Der Speicher ersetzt die BPF-Systemaufrufe;
die Kapazitätsablehnung und Wiederherstellung mit echten Maps prüft LOAD-01.
Sieben zusätzliche Regressionstests prüfen Ablehnung vor jeder Map-Veränderung,
dynamische Kapazitätsberechnung, fehlgeschlagene Generations-/Belegungsabfragen,
Updatefehler ohne Trigger mit erfolgreichem Folgeupdate sowie weiterhin fatale
Initialisierungs- und Benachrichtigungsfehler.

### 3.4 Trigger-Kanal zwischen Loadern und Userspace-PEP

**Datei:** `tails-pdp-userspace-common/src/lib.rs`  
**Anzahl:** 2 Tests  
**Art:** Unit-Tests

| Testfunktion | Geprüftes Verhalten | Status |
|---|---|---|
| `bounded_trigger_channel_coalesces_without_growing` | Der begrenzte Kanal nimmt einen Trigger auf und koalesziert weitere Trigger bei voller Kapazität | Implementiert |
| `closed_trigger_channel_is_an_error` | Ein geschlossener Empfänger wird als Fehler gemeldet | Implementiert |

**Aussagekraft:** Geprüft wird die isolierte Kanalsemantik, nicht die vollständige
Ereigniskette von einer Dateiänderung bis zum nachfolgenden `/proc`-Scan.

### 3.5 Userspace-PEP und FD-Enforcement

**Datei:** `tails-pdp-userspace-pep/src/pep.rs`  
**Anzahl:** 14 Tests (einschließlich `src/evaluation_tests.rs`)
**Art:** Unit- und asynchrone Komponententests; Enforcementtests mit `FakeFdCloser`

| Testfunktion | Geprüftes Verhalten | Status |
|---|---|---|
| `parses_only_numeric_process_and_fd_names` | Nur numerische Prozess- und FD-Verzeichnisnamen werden akzeptiert | Implementiert |
| `process_subject_uses_real_uid_from_proc_status` | Auswahl der Real UID aus dem ersten Feld der `Uid:`-Zeile in `/proc/<pid>/status` | Implementiert |
| `regular_files_are_identified_but_directories_are_ignored` | Reguläre Dateien werden als Ressourcen erkannt, Verzeichnisse werden ignoriert | Implementiert |
| `violation_targets_exactly_the_matching_file_descriptor` | Ein Verstoß enthält genau die ermittelte PID und FD-Nummer | Implementiert |
| `same_file_descriptor_is_closed_only_once_per_scan` | Mehrere passende Policies führen innerhalb eines Scans nur zu einem Schließversuch pro FD | Implementiert |
| `other_file_descriptors_remain_independently_enforceable` | Unterschiedliche FDs desselben Prozesses werden unabhängig behandelt | Implementiert |
| `failed_close_is_attempted_once_without_aborting_scan` | Ein fehlgeschlagener Schließversuch wird nicht wiederholt und bricht die übrige Verarbeitung nicht ab | Implementiert |
| `schedules_hour_policy_at_the_next_decision_change` | Nächste relevante Zeitgrenze einer Stundenbedingung | Implementiert |
| `schedules_modulo_policy_at_the_next_truth_value_change` | Nächster Wahrheitswertwechsel einer Modulo-Zeitbedingung | Implementiert |
| `does_not_schedule_constant_time_conditions` | Für zeitlich konstante Bedingungen wird keine unnötige Grenze eingeplant | Implementiert |
| `waits_without_scanning_when_no_trigger_arrives` | Ohne Trigger bleibt der Userspace-PEP inaktiv und startet keinen Scan | Implementiert |
| `closed_trigger_channel_is_reported` | Ein geschlossener Trigger-Kanal beendet das Warten mit einem expliziten Fehler | Implementiert |

**Ergänzungen in `src/evaluation_tests.rs`:**

| Testfunktion | Geprüftes Verhalten | Status |
|---|---|---|
| `comp03_all_conditions_required_with_missing_wrong_type_and_wrong_value` | Vier Bedingungen im produktiven Lookup-Ablauf, jedes fehlende/falsche Attribut sowie falsche UID und Bank | Implementiert |
| `failed_close_does_not_prevent_another_target_from_being_attempted` | Nach einem fehlgeschlagenen Entzug wird ein anderer Prozess weiterhin verarbeitet | Implementiert |

**Aussagekraft:** Die Auswahl und Deduplizierung von Entzugszielen sowie das
Trigger- und Zeitverhalten werden isoliert geprüft. Der `FakeFdCloser` führt keinen
realen `ptrace`-basierten `close`-Systemaufruf aus. Dieser wird nur im
End-to-End-Szenario mit einem realen Hilfsprozess geprüft.

## 4. Privilegierte End-to-End-Tests

**Dateien:** `test-e2e.sh`, `tests/e2e/lib.sh` und je Test-ID ein Szenarioskript in `tests/e2e/`

**Art:** System- und End-to-End-Tests  
**Voraussetzung:** dediziertes Linux-Testsystem mit BPF-LSM, BTF, bpffs und
Root-Rechten

Das Skript startet die Release-Runtime in einem temporären Arbeitsverzeichnis. Es
verwendet reale gepinnte Maps unter `/sys/fs/bpf/tails-pdp`, hängt den tatsächlichen
`file_open`-Hook an und startet für den FD-Entzug einen realen Hilfsprozess.

| Test-ID / Skript | Szenario | Geprüftes Verhalten | Beobachtungskriterium | Status |
|---|---|---|---|---|
| E2E-01 `E2E-01.sh` | Runtime-Start, Verifier und Attach | Das eBPF-Objekt wird vom Kernel akzeptiert, die Runtime bleibt aktiv und die erwarteten Maps sind gepinnt | Startmeldung im Runtime-Log und Existenz aller Map-Pfade | Implementiert |
| E2E-02 `E2E-02.sh` | Leerer Policystand | Ohne aktive Deny-Policy bleibt der Dateizugriff erlaubt | Lesen der Testdatei ist erfolgreich | Implementiert |
| E2E-03 `E2E-03.sh` | Statische Deny-Policy | Hinzufügen einer statischen Policy führt zur Ablehnung einer neuen Dateiöffnung; Entfernen erlaubt sie wieder | Lesen schlägt nach Aktivierung fehl und funktioniert nach Entfernung wieder | Implementiert |
| E2E-04 `E2E-04.sh` | Aktuelle UTC-Stunde | Der Kernelpfad verwendet `CURRENT_TIME` für eine Policy zur aktuellen UTC-Stunde | Zugriff wird während der passenden Stunde verweigert | Implementiert |
| E2E-05 `E2E-05.sh` | Dynamisches Systemattribut | Änderung von `system.defcon` verändert die reale Zugriffsentscheidung in beide Richtungen | DEFCON 5 erlaubt, DEFCON 2 verweigert, Rückkehr zu 5 erlaubt | Implementiert |
| E2E-06 `E2E-06.sh` | Frei benanntes Subject-Attribut | Das Attribut `subject.position` wird für die UID des Testprozesses geladen und bei Änderungen neu ausgewertet | `engineer` erlaubt, `intern` verweigert, Rückkehr zu `engineer` erlaubt | Implementiert |
| E2E-07 `E2E-07.sh` | Frei benanntes Resource-Attribut | Das Attribut `resource.classification` wird anhand von Device und Inode der Testdatei ausgewertet | `public` erlaubt, `internal` verweigert, Rückkehr zu `public` erlaubt | Implementiert |
| E2E-08 `E2E-08.sh` | Ungültige Policygeneration | Eine syntaktisch ungültige Änderung ersetzt die zuvor gültige Generation nicht und beendet die Runtime nicht | Fehlermeldung im Log und vorheriges Deny bleibt wirksam | Implementiert |
| E2E-09 `E2E-09.sh` | Nachträglicher selektiver FD-Entzug | Der Userspace-PEP schließt einen bereits geöffneten, nachträglich unzulässigen FD; ein zweiter erlaubter FD bleibt geöffnet | Hilfsprozess meldet `target_closed=True safe_open=True` | Implementiert |
| E2E-10 `E2E-10.sh` | Administrationsschnittstelle | `show-active` zeigt Generationen, aktive Policy, Ressource und Systemattribut an, ohne Generation oder Entscheidung zu verändern | Erwartete Textbestandteile, identische Generationen vor und nach erneutem Aufruf sowie weiterhin wirksames Deny | Implementiert |

### Sicherheits- und Ausführungsgrenzen

Der End-to-End-Test verändert vorübergehend globalen BPF-Zustand. Er darf nicht
parallel zu einer regulären Instanz und nicht auf einem Produktivsystem ausgeführt
werden. Das Skript prüft dies teilweise, indem es bei einer bereits laufenden
`tails-pdp`-Runtime abbricht und beim Beenden nur selbst gestartete Prozesse stoppt.

### Aussagegrenzen des bisherigen End-to-End-Tests

Die zehn bisherigen Szenarien sind gezielte Funktionsnachweise, keine quantitative
Evaluation. Abschnitt 5 ergänzt die bisher offenen Prüfungen. Messungen und
Charakterisierung bleiben auf die konkrete Zielumgebung begrenzt.

## 5. Ergänzend implementierte Tests

Die folgenden 18 Vorschläge wurden umgesetzt. Priorität und Aufwand bleiben als
ursprüngliche Planungseinschätzung erhalten. Der Status bezeichnet vorhandenen
Testcode und ist ausdrücklich kein Bestehensnachweis.

COMP-01 bis COMP-03 laufen über `./test.sh`. Alle anderen IDs dieses Abschnitts
laufen über `sudo ./test-evaluation.sh`, optional gefolgt von einzelnen
IDs. Details zu Parametern und Beobachtungsgrenzen stehen in
[`tests/evaluation/README.md`](../tests/evaluation/README.md).

### 5.1 Funktions- und Komponententests

| Test-ID | Vorgeschlagener Test | Erwartetes Ergebnis | Bezug | Priorität | Aufwand | Status |
|---|---|---|---|---:|---:|---|
| COMP-01 | Rekursives Einlesen eines vollständigen Attributverzeichnisses mit System-, Subject- und Resource-Dateien | Nur gültige Dateien werden eingelesen und den korrekten Namespaces sowie Objektidentifikatoren zugeordnet | FA-05, FA-10 | B | mittel | Implementiert |
| COMP-02 | Transaktionaler Wechsel der Attributgeneration mit simuliertem Schreib- oder Aktivierungsfehler | Eine fehlerhafte Attributgeneration wird nicht aktiviert; die letzte gültige Generation bleibt sichtbar | FA-05, FA-08, OA-01 | A | mittel bis hoch | Implementiert |
| COMP-03 | Kombination mehrerer dynamischer Bedingungen in einer Policy | Die Policy greift nur, wenn alle Bedingungen erfüllt sind; Typabweichungen oder fehlende Attribute führen zu keinem Match | FA-04, FA-05 | A | klein | Implementiert |
| COMP-04 | Ausgabevarianten des Administrationstools (`show`, `show-policies`, `show-attributes`) | Aktive Bank, Policies und Attribute werden je Unterbefehl vollständig und ohne Zustandsänderung ausgegeben | FA-07, OA-02 | B | klein | Implementiert |

### 5.2 Weitere End-to-End-Tests

| Test-ID | Vorgeschlagenes Szenario | Erwartetes Ergebnis | Bezug | Priorität | Aufwand | Status |
|---|---|---|---|---:|---:|---|
| E2E-11 | Mehrere gleichzeitig aktive Policies einschließlich Permit und Deny | Die reale Kernelentscheidung folgt der Combining-Regel `deny-overrides`; nach Entfernen des Deny ist der Zugriff wieder erlaubt | FA-04 | A | klein | Implementiert |
| E2E-12 | Gemeinsame Policy mit System-, Subject- und Resource-Attribut | Der Zugriff wird nur verweigert, wenn die gesamte Attributkonjunktion erfüllt ist; die Änderung jedes einzelnen Attributs wird wirksam | FA-04, FA-05, FA-10 | A | mittel | Implementiert |
| E2E-13 | Ungültiges Update einer Attributdatei | Die Runtime bleibt aktiv, meldet den Fehler und verwendet weiterhin die letzte gültige Attributgeneration | FA-05, FA-08, OA-01 | A | mittel | Implementiert |
| E2E-14 | Nachvollziehbarkeit einer konkreten Ablehnung | Log oder Administrationsausgabe macht erkennbar, welche Policy beziehungsweise welcher Zustand die Entscheidung beeinflusst hat | OA-02 | A | mittel; gegebenenfalls Implementierungsänderung nötig | Implementiert |
| E2E-15 | Unterschiedliche Real und Effective UID eines Hilfsprozesses | Die Entscheidung verwendet entsprechend der dokumentierten Semantik die Real UID | FA-03, FA-04 | B | mittel; separater Benutzer nötig | Implementiert |
| E2E-16 | Mehrere bereits geöffnete, verletzende und weiterhin erlaubte File Descriptors | Alle verletzenden FDs werden entzogen, während nicht betroffene FDs geöffnet bleiben | FA-06 | B | mittel | Implementiert |
| E2E-17 | Zielprozess kann nicht mit `ptrace` erreicht werden | Der Fehler wird protokolliert; Runtime, Kernel und die Verarbeitung weiterer Prozesse bleiben funktionsfähig | FA-06, OA-01 | B | mittel; angepasste Schutzdomäne nötig | Implementiert |
| CHAR-01 | Charakterisierung von `dup()`, FD-Vererbung, `fork()` und `mmap()` | Das beobachtete Verhalten und die Grenzen des prototypischen FD-Enforcements werden reproduzierbar dokumentiert | FA-06, Prototypgrenzen | C | hoch | Implementiert |
| RACE-01 | Parallele Dateioperationen und Wiederverwendung derselben FD-Nummer während eines Scans | Kein falscher FD wird geschlossen; erkannte Restrisiken werden dokumentiert | FA-06, OA-01 | C | hoch | Implementiert |

### 5.3 Performance-, Last- und Stabilitätstests

| Test-ID | Vorgeschlagener Test | Messgröße beziehungsweise Erwartung | Bezug | Priorität | Aufwand | Status |
|---|---|---|---|---:|---:|---|
| PERF-01 | Mikrobenchmark kontrollierter Dateiöffnungen ohne Runtime, mit Runtime ohne passende Policy und mit passender Allow-Policy | Laufzeit pro `open()` beziehungsweise `openat()`, Median sowie geeignete Perzentile; relativer Overhead gegenüber der Baseline | OA-03 | A | mittel | Implementiert |
| PERF-02 | Reaktionslatenz nach einer Policy- und nach einer Attributänderung | Zeit von der atomaren Dateiänderung bis zur beobachtbaren neuen Zugriffsentscheidung, jeweils über mehrere Wiederholungen | FA-02, FA-05, OA-03 | A | mittel | Implementiert |
| PERF-03 | Entzugslatenz eines bereits geöffneten FDs | Zeit von der aktivierten verletzenden Änderung bis zum festgestellten `EBADF`, jeweils über mehrere Wiederholungen | FA-06, OA-03 | A | mittel | Implementiert |
| LOAD-01 | Reale Belegung bis an die dokumentierten Policy- und Attributkapazitäten | Grenzwerte werden akzeptiert; Überschreitungen werden kontrolliert abgelehnt und verändern die aktive Generation nicht | FA-08, FA-09, OA-01 | B | mittel | Implementiert |
| STAB-01 | Wiederholte gültige und ungültige Policy- sowie Attributwechsel über einen längeren Lauf | Keine Runtime-Beendigung, kein Kernelproblem und konsistente letzte Generation nach jedem Wechsel | OA-01, OA-04 | B | mittel bis hoch | Implementiert |

COMP-04 wird gegen echte Maps geprüft und benötigt daher Root. E2E-15 verwendet
numerische Real UIDs bei Effective UID 0 ohne neue Benutzerkonten. E2E-17 erzeugt
den Attach-Fehler durch einen bereits vorhandenen Tracer. PERF-03 protokolliert
ein Intervall für die Aktivierung-bis-EBADF-Latenz. RACE-01 kann eine beobachtete
Fehlrevokation nachweisen, aber durch einen erfolgreichen Lauf keine Race-Freiheit
beweisen. LOAD-01 unterscheidet 1024 gesamte Map-Einträge von 512 Einträgen pro
Bank bei vollständiger Doppelbelegung.

## 6. Statische Qualitäts- und Build-Prüfungen

**Datei:** `test.sh`

`test.sh` führt neben den 59 Rust-Tests weitere Prüfschritte aus:

| Prüfschritt | Kommando | Bedeutung | Abgrenzung | Status |
|---|---|---|---|---|
| Formatprüfung | `cargo fmt --all -- --check` | Prüft die einheitliche Formatierung aller Rust-Dateien | Keine funktionale Verhaltensprüfung | Implementiert |
| Unit- und Komponententests | `cargo test --locked ... --all-targets` | Führt die oben aufgelisteten Rust-Tests aus | Lädt kein eBPF-Programm in den Kernel | Implementiert |
| Clippy | `cargo clippy --locked ... --all-targets -- -D warnings` | Statische Analyse; alle Warnungen werden als Fehler behandelt | Kein Nachweis des Laufzeitverhaltens | Implementiert |
| Release-Build | `cargo build --locked --release ...` | Baut Userspace-Binaries und über `build.rs` das eingebettete eBPF-Objekt | Belegt Übersetzbarkeit, aber nicht die Annahme durch den Kernel-Verifier | Implementiert |

Die vollständige Prüfkette ist für Linux vorgesehen. Auf macOS kann das Projekt
teilweise für Linux cross-kompiliert werden; Verifier-, Attach- und reale
Enforcement-Nachweise benötigen jedoch das Linux-Zielsystem.

## 7. Abdeckung der Anforderungen aus Kapitel 3

Die folgende Zuordnung zeigt, für welche Anforderungen bereits automatisierte
Evidenz vorhanden ist. Sie stellt noch keine abschließende Bewertung als
„erfüllt“ dar; dafür müssen die Tests auf der dokumentierten Zielumgebung
ausgeführt und ihre Ergebnisse berichtet werden.

| Anforderung | Vorhandene Testevidenz | Art der Evidenz | Noch offene Punkte |
|---|---|---|---|
| FA-01 Policy-Einlesen | Rekursives Einlesen von `.policy`-Dateien; E2E-Aktivierung einer neuen Policy | Komponente + E2E | Keine wesentliche Lücke für den definierten Umfang |
| FA-02 Policy-Verwaltung | E2E-Hinzufügen und Entfernen; Unit-Tests zu Änderungserkennung und Generationen | Komponente + E2E | Schnelle parallele Änderungen nicht gezielt getestet |
| FA-03 Kontrolle bei Dateiöffnungen | Statische E2E-Deny-Policy über den realen `file_open`-Hook | E2E | Nur der vorgesehene Hook und das Zielsystem |
| FA-04 Policybasierte Entscheidung | Gemeinsame Logik sowie E2E-11 und E2E-12: deny-overrides und Attributkonjunktion | Unit + E2E | Kombinationen nur für die ausgewählten Fälle nachgewiesen |
| FA-05 Dynamische Attribute | COMP-01 bis COMP-03, E2E-12 und E2E-13: Verzeichnisse, Commitfehler, Konjunktion und ungültige Updates | Komponente + E2E | LOAD-01 prüft jetzt kontrollierte Kapazitätsablehnung und Folgeupdates; alte Fehlerevidenz bleibt archiviert |
| FA-06 Bestehende Dateizugriffe | Selektiver Mehrfachentzug, ptrace-Fehlerpfad, CHAR-01, RACE-01 und PERF-03 | Komponente + E2E + Messung | mmap bleibt lesbar; Race-Freiheit nicht bewiesen |
| FA-07 Administrationsschnittstelle | E2E-10 und COMP-04 prüfen Inhalte, Ausgabevarianten und unveränderte Generationen | E2E | Zustandsanzeige ist kein individuelles Entscheidungs-Auditlog |
| FA-08 Gültige Generationen | Policy- und Attribut-Commitfehler mit Testdoubles; reale ungültige Updates und Kapazitätsfehler | Komponente + E2E | LOAD-01 prüft unveränderte Attributwerte und Generation bei Ablehnung; parallele Updates während eines Scans nicht vollständig abgedeckt |
| FA-09 Validierung von Policies | Parser-, Wertebereichs- und reale Kapazitätstests beider Policyarten | Komponente + E2E | Manipulation echter Maps durch externe Programme ist nicht Teil der Tests |
| FA-10 Beliebige Attributnamen | Übersetzung und reale Auswertung frei benannter Subject-/Resource-Attribute; 512 Systemattribute in LOAD-01 | Komponente + E2E | Endliche Namensstichprobe |
| OA-01 Stabilität | E2E-13, E2E-17 und STAB-01 sowie korrigierter LOAD-01 | E2E | Ergebnisse der Korrektur separat dokumentiert; 100 Zyklen sind kein Langzeitnachweis |
| OA-02 Beobachtbarkeit | E2E-14 rekonstruiert Deny aus eindeutiger aktiver Policy, Bedingung und Attributwert | E2E | Kein individuelles Auditlog jeder Dateiöffnung |
| OA-03 Performance | PERF-01 bis PERF-03 mit Rohdaten und Zeitmessungen | Messung | Python-/Pollingaufwand, sequenzielle Benchmarkphasen und kleine Latenzstichprobe; keine SLA-Vorgabe |
| OA-04 Reproduzierbarkeit | Skripte, isolierte Testverzeichnisse, Zielsystemdaten und archivierte Rohdaten | Testinfrastruktur | Übernahme der Ergebnisse in Kapitel 6 bleibt redaktionelle Arbeit außerhalb dieser Testimplementierung |
| EA-01 bis EA-03 | Keine direkten Tests | analytisch zu bewerten | Modularität, Erweiterbarkeit und begrenzter Kernelanteil anhand des Entwurfs diskutieren |

## 8. Zusammenfassung des aktuellen Teststands

Der bestehende Testbestand deckt die zentralen funktionalen Pfade des Prototyps
bereits auf zwei Ebenen ab. Die Rust-Tests prüfen insbesondere Policysemantik,
Validierung, Generationenkonsistenz und die isolierte Logik des Userspace-PEP. Der
privilegierte End-to-End-Test ergänzt den Nachweis, dass der Zielkernel das
eBPF-Programm akzeptiert, neue Dateiöffnungen tatsächlich kontrolliert werden und
ein bereits geöffneter File Descriptor in einem kontrollierten Szenario selektiv
geschlossen wird.

Die ehemals offenen Tests sind jetzt automatisiert. Die Auswertung in
[Testbewertung.md](Testbewertung.md) trennt bestandene Szenarien, fehlgeschlagene
Anforderungen und Messgrenzen. Insbesondere ein bestandener Race-Stresstest oder
ein zeitlich begrenzter Stabilitätslauf ist kein allgemeiner Produktionsnachweis.

# Übersicht der aktuell implementierten Tests

## 1. Zweck und Abgrenzung

Dieses Dokument erfasst die im Repository aktuell implementierten Tests und
Qualitätsprüfungen. Die Übersicht beruht auf dem Quellstand vom 8. September 2026.
Sie beschreibt, **was implementiert ist**, nicht ob ein konkreter Testlauf auf dem
Zielsystem erfolgreich war. Die Ergebnisse eines ausgeführten Testlaufs müssen für
die Evaluation gesondert protokolliert werden.

Der Testbestand ist in drei Ebenen gegliedert:

1. **Unit- und Komponententests** prüfen isolierte Logik in Rust, teilweise mit
   Testdoubles statt realer BPF-Maps oder eines realen FD-Entzugs.
2. **Privilegierte End-to-End-Tests** starten die vollständige Runtime auf einem
   Linux-Zielsystem und prüfen den echten eBPF-LSM-Hook sowie den Userspace-PEP.
3. **Statische Qualitäts- und Build-Prüfungen** prüfen Formatierung, Lints und
   Übersetzbarkeit. Sie sind keine funktionalen Laufzeittests im engeren Sinn.

Aktuell sind **46 Rust-Tests** in fünf Testmodulen sowie **sieben
End-to-End-Szenarien** in `test-e2e.sh` vorhanden.

## 2. Übersicht nach Testart

| Testart | Ausführung | Anzahl | Benötigt Root? | Hauptzweck |
|---|---|---:|---:|---|
| Unit- und Komponententests | `./test.sh` bzw. `cargo test` | 46 | nein | Isolierte Prüfung von Policylogik, Parsern, Generationen und Userspace-PEP |
| End-to-End-Tests | `sudo ./test-e2e.sh` | 7 Szenarien | ja | Reales Laden, Anhängen und Durchsetzen auf dem Linux-Zielkernel |
| Formatprüfung | Teil von `./test.sh` | 1 Prüfschritt | nein | Einheitliche Rust-Formatierung |
| Clippy | Teil von `./test.sh` | 1 Prüfschritt | nein | Statische Analyse mit Warnungen als Fehler |
| Release-Build | Teil von `./test.sh` | 1 Prüfschritt | nein | Übersetzung der Userspace-Binaries und des eingebetteten eBPF-Objekts |

## 3. Unit- und Komponententests

### 3.1 Gemeinsame Policy- und Entscheidungslogik

**Datei:** `tails-pdp-common/src/lib.rs`  
**Anzahl:** 16 Tests  
**Art:** Unit-Tests

Die Funktionen dieses Crates werden teilweise sowohl vom Kernelspace- als auch vom
Userspace-Pfad verwendet. Die Tests prüfen die gemeinsame Daten- und
Entscheidungssemantik ohne einen geladenen LSM-Hook.

| Testfunktion | Geprüftes Verhalten |
|---|---|
| `policy_time_derives_utc_components_from_unix_seconds` | Ableitung von Stunde, Minute und Sekunde aus einem Unix-Zeitstempel sowie Tageswechsel |
| `decision_state_uses_deny_overrides` | Combining-Regel: keine Entscheidung und Permit erlauben; ein Deny überstimmt Permit |
| `file_open_static_policy_matches_all_request_fields` | Matching einer statischen Datei-Policy anhand von UID, Kommando, Device und Inode; Nicht-Matches werden abgewiesen |
| `any_subject_static_policy_matches_every_uid` | `ANY_SUBJECT` passt auf unterschiedliche UIDs |
| `utc_component_policies_respect_operator_boundaries` | Vergleichsoperatoren an Grenzwerten einer UTC-Stundenbedingung |
| `attribute_conditions_match_numbers_and_booleans` | Vergleiche dynamischer Zahlen- und Boolean-Attribute |
| `attribute_conditions_match_string_hashes_only_by_equality` | Stringattribute werden über Hashwerte und ausschließlich mit Gleichheit verglichen |
| `attribute_conditions_reject_type_mismatches` | Unterschiedliche Attributtypen führen zu keinem Match |
| `attribute_object_ids_are_namespace_scoped` | Objektidentifikatoren unterscheiden System-, Subject- und Resource-Namespace |
| `stream_policy_with_dynamic_attributes_requires_map_lookup` | Eine Policy mit dynamischem Attribut kann ohne Attribut-Lookup nicht abschließend ausgewertet werden |
| `stream_policy_returns_entitlement_when_condition_matches` | Eine passende zeitabhängige Bedingung liefert das Policy-Entitlement |
| `stream_policy_uses_utc_hour_from_shared_policy_time` | Stream-Policy verwendet die Stunde aus der gemeinsamen Zeitrepräsentation |
| `stream_policy_is_not_applicable_when_condition_does_not_match` | Eine nicht erfüllte Stream-Bedingung macht die Policy nicht anwendbar |
| `stream_policy_with_zero_modulo_is_not_applicable` | Defensives Verhalten bei einem Modulo-Wert von null |
| `file_open_stream_policy_respects_command_filter` | Kommando-Filter einer zeitabhängigen `file_open`-Policy |
| `socket_bind_stream_policy_respects_command_filter` | Kommando-Filter der vorhandenen gemeinsamen `socket_bind`-Policylogik |

**Aussagekraft:** Die Tests belegen die isolierte Policysemantik. Sie belegen nicht,
dass der Kernel-Verifier das eBPF-Programm akzeptiert, dass BPF-Maps korrekt gelesen
werden oder dass der LSM-Hook eine reale Dateiöffnung verhindert.

### 3.2 Einlesen, Parsen und Aktivieren von Policies

**Datei:** `tails-pdp-policy-loader/src/policy_source.rs`  
**Anzahl:** 14 Tests  
**Art:** Unit- und Komponententests; Generationstests mit `FakePolicyStore`

| Testfunktion | Geprüftes Verhalten |
|---|---|
| `translates_dynamic_subject_attribute` | Übersetzung eines frei benannten Subject-Attributs in die interne Stream-Policy-Repräsentation |
| `rejects_unsupported_attribute_name` | Ablehnung eines Attributnamens mit nicht unterstützten Zeichen |
| `translates_static_and_time_policies` | Gemeinsame Übersetzung einer statischen und einer zeitabhängigen Datei-Policy |
| `rejects_duplicate_policy_names` | Ablehnung doppelter Policynamen |
| `rejects_missing_semicolon_and_unknown_action` | Ablehnung eines fehlenden Semikolons und einer nicht unterstützten Action |
| `rejects_disabled_socket_bind_action` | Explizite Ablehnung der derzeit deaktivierten `socket_bind`-Action |
| `rejects_too_many_dynamic_conditions_and_policies` | Durchsetzung der Grenzen für dynamische Bedingungen und Policies pro Bank |
| `rejects_invalid_time_ranges_and_zero_modulo` | Ablehnung ungültiger UTC-Werte und eines Modulo-Werts von null |
| `reads_only_policy_files_recursively` | Rekursives Einlesen ausschließlich von Dateien mit der Endung `.policy` |
| `generation_is_activated_only_after_bank_write` | Neue Generation wird erst nach dem Schreiben der inaktiven Bank aktiviert |
| `failed_bank_write_keeps_previous_generation_active` | Ein Schreibfehler verändert die aktive Generation nicht |
| `failed_activation_does_not_report_new_generation` | Ein Aktivierungsfehler wird nicht als erfolgreiche neue Generation gemeldet |
| `unchanged_and_repeatedly_failed_documents_are_not_retried` | Unveränderte sowie bereits fehlgeschlagene Dokumentstände werden nicht erneut synchronisiert |
| `preparing_bank_disables_entries_after_last_policy` | Freie Einträge einer vorbereiteten Policybank werden deaktiviert, sodass alte Policies nicht bestehen bleiben |

**Aussagekraft:** Parser, Übersetzung und Reihenfolge eines Generationenwechsels
werden isoliert geprüft. Die Generationstests verwenden keine realen BPF-Maps; die
Aktivierung auf echten gepinnten Maps wird ergänzend durch den End-to-End-Test
abgedeckt.

### 3.3 Verarbeitung dynamischer Attributdateien

**Datei:** `tails-pdp-attribute-loader/src/stream_attributes.rs`  
**Anzahl:** 2 Tests  
**Art:** Unit-Tests

| Testfunktion | Geprüftes Verhalten |
|---|---|
| `parses_supported_attribute_values` | Parsen von Zahlen, Boolean-Werten und gehashten Stringwerten |
| `validates_attribute_names_and_defcon_range` | Zulässige und unzulässige Attributnamen sowie Wertebereich von `system.defcon` |

**Aussagekraft:** Die elementare Wert- und Namensvalidierung wird geprüft. Nicht
durch Unit-Tests abgedeckt sind insbesondere das vollständige rekursive Einlesen
aller Attributdateien, der reale Wechsel der Attributbank und Fehler beim Schreiben
der echten BPF-Attributmap.

### 3.4 Trigger-Kanal zwischen Loadern und Userspace-PEP

**Datei:** `tails-pdp-userspace-common/src/lib.rs`  
**Anzahl:** 2 Tests  
**Art:** Unit-Tests

| Testfunktion | Geprüftes Verhalten |
|---|---|
| `bounded_trigger_channel_coalesces_without_growing` | Der begrenzte Kanal nimmt einen Trigger auf und koalesziert weitere Trigger bei voller Kapazität |
| `closed_trigger_channel_is_an_error` | Ein geschlossener Empfänger wird als Fehler gemeldet |

**Aussagekraft:** Geprüft wird die isolierte Kanalsemantik, nicht die vollständige
Ereigniskette von einer Dateiänderung bis zum nachfolgenden `/proc`-Scan.

### 3.5 Userspace-PEP und FD-Enforcement

**Datei:** `tails-pdp-userspace-pep/src/pep.rs`  
**Anzahl:** 12 Tests  
**Art:** Unit- und asynchrone Komponententests; Enforcementtests mit `FakeFdCloser`

| Testfunktion | Geprüftes Verhalten |
|---|---|
| `parses_only_numeric_process_and_fd_names` | Nur numerische Prozess- und FD-Verzeichnisnamen werden akzeptiert |
| `process_subject_uses_real_uid_from_proc_status` | Auswahl der Real UID aus dem ersten Feld der `Uid:`-Zeile in `/proc/<pid>/status` |
| `regular_files_are_identified_but_directories_are_ignored` | Reguläre Dateien werden als Ressourcen erkannt, Verzeichnisse werden ignoriert |
| `violation_targets_exactly_the_matching_file_descriptor` | Ein Verstoß enthält genau die ermittelte PID und FD-Nummer |
| `same_file_descriptor_is_closed_only_once_per_scan` | Mehrere passende Policies führen innerhalb eines Scans nur zu einem Schließversuch pro FD |
| `other_file_descriptors_remain_independently_enforceable` | Unterschiedliche FDs desselben Prozesses werden unabhängig behandelt |
| `failed_close_is_attempted_once_without_aborting_scan` | Ein fehlgeschlagener Schließversuch wird nicht wiederholt und bricht die übrige Verarbeitung nicht ab |
| `schedules_hour_policy_at_the_next_decision_change` | Nächste relevante Zeitgrenze einer Stundenbedingung |
| `schedules_modulo_policy_at_the_next_truth_value_change` | Nächster Wahrheitswertwechsel einer Modulo-Zeitbedingung |
| `does_not_schedule_constant_time_conditions` | Für zeitlich konstante Bedingungen wird keine unnötige Grenze eingeplant |
| `waits_without_scanning_when_no_trigger_arrives` | Ohne Trigger bleibt der Userspace-PEP inaktiv und startet keinen Scan |
| `closed_trigger_channel_is_reported` | Ein geschlossener Trigger-Kanal beendet das Warten mit einem expliziten Fehler |

**Aussagekraft:** Die Auswahl und Deduplizierung von Entzugszielen sowie das
Trigger- und Zeitverhalten werden isoliert geprüft. Der `FakeFdCloser` führt keinen
realen `ptrace`-basierten `close`-Systemaufruf aus. Dieser wird nur im
End-to-End-Szenario mit einem realen Hilfsprozess geprüft.

## 4. Privilegierte End-to-End-Tests

**Datei:** `test-e2e.sh`  
**Art:** System- und End-to-End-Tests  
**Voraussetzung:** dediziertes Linux-Testsystem mit BPF-LSM, BTF, bpffs und
Root-Rechten

Das Skript startet die Release-Runtime in einem temporären Arbeitsverzeichnis. Es
verwendet reale gepinnte Maps unter `/sys/fs/bpf/tails-pdp`, hängt den tatsächlichen
`file_open`-Hook an und startet für den FD-Entzug einen realen Hilfsprozess.

| Nr. | Szenario | Geprüftes Verhalten | Beobachtungskriterium |
|---:|---|---|---|
| 1 | Runtime-Start, Verifier und Attach | Das eBPF-Objekt wird vom Kernel akzeptiert, die Runtime bleibt aktiv und die erwarteten Maps sind gepinnt | Startmeldung im Runtime-Log und Existenz aller Map-Pfade |
| 2 | Leerer Policystand | Ohne aktive Deny-Policy bleibt der Dateizugriff erlaubt | Lesen der Testdatei ist erfolgreich |
| 3 | Statische Deny-Policy | Hinzufügen einer statischen Policy führt zur Ablehnung einer neuen Dateiöffnung; Entfernen erlaubt sie wieder | Lesen schlägt nach Aktivierung fehl und funktioniert nach Entfernung wieder |
| 4 | Aktuelle UTC-Stunde | Der Kernelpfad verwendet `CURRENT_TIME` für eine Policy zur aktuellen UTC-Stunde | Zugriff wird während der passenden Stunde verweigert |
| 5 | Dynamisches Systemattribut | Änderung von `system.defcon` verändert die reale Zugriffsentscheidung in beide Richtungen | DEFCON 5 erlaubt, DEFCON 2 verweigert, Rückkehr zu 5 erlaubt |
| 6 | Ungültige Policygeneration | Eine syntaktisch ungültige Änderung ersetzt die zuvor gültige Generation nicht und beendet die Runtime nicht | Fehlermeldung im Log und vorheriges Deny bleibt wirksam |
| 7 | Nachträglicher selektiver FD-Entzug | Der Userspace-PEP schließt einen bereits geöffneten, nachträglich unzulässigen FD; ein zweiter erlaubter FD bleibt geöffnet | Hilfsprozess meldet `target_closed=True safe_open=True` |

### Sicherheits- und Ausführungsgrenzen

Der End-to-End-Test verändert vorübergehend globalen BPF-Zustand. Er darf nicht
parallel zu einer regulären Instanz und nicht auf einem Produktivsystem ausgeführt
werden. Das Skript prüft dies teilweise, indem es bei einer bereits laufenden
`tails-pdp`-Runtime abbricht und beim Beenden nur selbst gestartete Prozesse stoppt.

### Aussagegrenzen des aktuellen End-to-End-Tests

Das Skript weist erfolgreiches Verhalten in den definierten Szenarien nach. Es
enthält aktuell jedoch keine:

- quantitative Messung der Reaktions- oder Entzugslatenz,
- Messung des Laufzeitaufwands von `open()` oder `openat()`,
- Last-, Langzeit- oder Skalierungstests,
- End-to-End-Prüfung frei benannter Subject- oder Resource-Attribute,
- privilegierte Credential-Prüfung mit unterschiedlicher Real und Effective UID,
- Race-Tests für FD-Wiederverwendung oder parallele Threads,
- Tests für `dup()`, FD-Vererbung, `mmap()` oder Namespace-Grenzen,
- Prüfung eines nicht mit `ptrace` erreichbaren Zielprozesses,
- gezielte Prüfung eines Ausfalls des Zeit- oder Attributaktualisierers.

## 5. Statische Qualitäts- und Build-Prüfungen

**Datei:** `test.sh`

`test.sh` führt neben den 46 Rust-Tests weitere Prüfschritte aus:

| Prüfschritt | Kommando | Bedeutung | Abgrenzung |
|---|---|---|---|
| Formatprüfung | `cargo fmt --all -- --check` | Prüft die einheitliche Formatierung aller Rust-Dateien | Keine funktionale Verhaltensprüfung |
| Unit- und Komponententests | `cargo test --locked ... --all-targets` | Führt die oben aufgelisteten Rust-Tests aus | Lädt kein eBPF-Programm in den Kernel |
| Clippy | `cargo clippy --locked ... --all-targets -- -D warnings` | Statische Analyse; alle Warnungen werden als Fehler behandelt | Kein Nachweis des Laufzeitverhaltens |
| Release-Build | `cargo build --locked --release ...` | Baut Userspace-Binaries und über `build.rs` das eingebettete eBPF-Objekt | Belegt Übersetzbarkeit, aber nicht die Annahme durch den Kernel-Verifier |

Die vollständige Prüfkette ist für Linux vorgesehen. Auf macOS kann das Projekt
teilweise für Linux cross-kompiliert werden; Verifier-, Attach- und reale
Enforcement-Nachweise benötigen jedoch das Linux-Zielsystem.

## 6. Abdeckung der Anforderungen aus Kapitel 3

Die folgende Zuordnung zeigt, für welche Anforderungen bereits automatisierte
Evidenz vorhanden ist. Sie stellt noch keine abschließende Bewertung als
„erfüllt“ dar; dafür müssen die Tests auf der dokumentierten Zielumgebung
ausgeführt und ihre Ergebnisse berichtet werden.

| Anforderung | Vorhandene Testevidenz | Art der Evidenz | Noch offene Punkte |
|---|---|---|---|
| FA-01 Policy-Einlesen | Rekursives Einlesen von `.policy`-Dateien; E2E-Aktivierung einer neuen Policy | Komponente + E2E | Keine wesentliche Lücke für den definierten Umfang |
| FA-02 Policy-Verwaltung | E2E-Hinzufügen und Entfernen; Unit-Tests zu Änderungserkennung und Generationen | Komponente + E2E | Schnelle parallele Änderungen nicht gezielt getestet |
| FA-03 Kontrolle bei Dateiöffnungen | Statische E2E-Deny-Policy über den realen `file_open`-Hook | E2E | Nur der vorgesehene Hook und das Zielsystem |
| FA-04 Policybasierte Entscheidung | Statische, zeitabhängige und dynamische Entscheidungen; `deny-overrides` | Unit + E2E | Keine vollständige Kombination aller Policyvarianten im E2E-Test |
| FA-05 Dynamische Attribute | Wertelogik in Unit-Tests; reales `system.defcon` im E2E-Test | Unit + E2E | Subject- und Resource-Attribute nicht End-to-End getestet |
| FA-06 Bestehende Dateizugriffe | Fake-FD-Enforcement sowie realer selektiver FD-Entzug | Komponente + E2E | Keine Zeitmessung; bekannte Race-, `dup`-, `fork`- und `mmap`-Grenzen |
| FA-07 Administrationsschnittstelle | `show-active` wird im E2E-Test erfolgreich aufgerufen | E2E-Smoke-Test | Inhalt und Nur-Lese-Eigenschaft werden nicht ausdrücklich assertiert |
| FA-08 Gültige Generationen | Reihenfolgentests mit Fake-Store und ungültiges Update im E2E-Test | Komponente + E2E | Mehrfachupdates während eines laufenden Scans nicht gezielt getestet |
| FA-09 Validierung von Policies | Umfangreiche Parser-, Wertebereichs- und Kapazitätstests | Unit/Komponente | Manipulation echter Maps ist nicht Teil der Tests |
| FA-10 Beliebige Attributnamen | Übersetzung von `subject.position`; Ablehnung ungültiger Zeichen | Unit | Kein realer E2E-Zugriff mit einem frei benannten Attribut |
| OA-01 Stabilität | Ungültiges Update beendet die Runtime im E2E-Test nicht | E2E | Kein Stress- oder Fuzz-Test; kein allgemeiner Stabilitätsnachweis |
| OA-02 Beobachtbarkeit | Runtime-Logs und erfolgreicher Aufruf von `show-active` | E2E-Smoke-Test | Ausgabequalität wird nicht automatisiert bewertet |
| OA-03 Performance | Keine entsprechende Messung implementiert | keine | Mikrobenchmark für kontrollierte Dateiöffnungen fehlt |
| OA-04 Reproduzierbarkeit | Automatisierte Skripte und temporäre Testumgebung vorhanden | Testinfrastruktur | Konkrete Zielsystemdaten und Messergebnisse müssen in Kapitel 6 ergänzt werden |
| EA-01 bis EA-03 | Keine direkten Tests | analytisch zu bewerten | Modularität, Erweiterbarkeit und begrenzter Kernelanteil anhand des Entwurfs diskutieren |

## 7. Zusammenfassung des aktuellen Teststands

Der bestehende Testbestand deckt die zentralen funktionalen Pfade des Prototyps
bereits auf zwei Ebenen ab. Die Rust-Tests prüfen insbesondere Policysemantik,
Validierung, Generationenkonsistenz und die isolierte Logik des Userspace-PEP. Der
privilegierte End-to-End-Test ergänzt den Nachweis, dass der Zielkernel das
eBPF-Programm akzeptiert, neue Dateiöffnungen tatsächlich kontrolliert werden und
ein bereits geöffneter File Descriptor in einem kontrollierten Szenario selektiv
geschlossen wird.

Für die Evaluation fehlen vor allem quantitative Messungen der Reaktionszeit und
des Laufzeitaufwands. Außerdem sind einige bekannte Grenzfälle des
Userspace-Entzugs nicht praktisch getestet. Diese können je nach Anspruch der
Arbeit durch wenige gezielte Zusatztests oder durch eine ausdrücklich analytische
Einordnung der Prototypgrenzen behandelt werden.

# Arbeiten in diesem Repository

- Kontext gezielt laden: zuerst Dateinamen und relevante Symbole mit `rg` suchen,
  dann nur benötigte Abschnitte lesen. Keine vollständigen Repository-Dumps.
- Codeaufgaben: mit dem betroffenen `tails-pdp*`-Crate und den passenden Tests
  beginnen. `thesis/` nur bei fachlichem Bezug oder ausdrücklichem Auftrag lesen.
- Thesis-Aufgaben: mit der betroffenen Datei in `thesis/sections/` beginnen;
  Code, Literatur und Testnachweise nur für die jeweiligen Aussagen hinzunehmen.
- `tails-pdp-ebpf/src/vmlinux.rs` enthält benötigte generierte Kernel-Typen.
  Nur gezielt nach Typen suchen; nicht vollständig lesen oder pauschal kürzen.
- Quellenkopien, `thesis/test-results/`, PDFs, Bilder, Archive, `target/`, `out/`
  und `tmp/` bei allgemeinen Suchen auslassen. Bei Bedarf ausdrücklich einbeziehen;
  Testrohdaten möglichst nach Szenario bzw. JSON-Feld auswerten.
- Requirements-Notizen liegen in `thesis/requirements-types-rules.md`.
- Toolausgaben kurz halten: relevante Treffer und Fehler ausgeben, große Logs
  in Dateien speichern und gezielt auswerten.
- Änderungen passend prüfen. `./test.sh` benötigt Linux; privilegierte
  E2E-/Evaluationstests benötigen das dedizierte Linux-Zielsystem.
  Bei reinen Dokumentations- und Artefaktänderungen genügen Diff-/Referenzprüfungen.
- Generierte Dateien und temporäre Ergebnisse nicht versionieren. Bestehende
  Nutzeränderungen und benötigte wissenschaftliche Nachweise erhalten.

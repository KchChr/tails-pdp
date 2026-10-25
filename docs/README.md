# Dokumentation für tails-pdp

Die Dokumentation besteht aus zwei eigenständigen Handbüchern und der Rustdoc-Referenz.

| Dokument | Inhalt | Bearbeitbare Quelle |
|---|---|---|
| Installationshandbuch | Voraussetzungen, drei Installationsschritte, Offline-Build, Startprobe und Diagnose | `../thesis/Christian_Koch_Installationshandbuch_tails-pdp.tex` |
| Programmierhandbuch | Architektur, Map-/Rust-Schnittstellen, Konfigurationsformate, Erweiterung und Grenzen | `../thesis/Christian_Koch_Programmierhandbuch_tails-pdp.tex` |
| Rustdoc | Crates, öffentliche Typen/Funktionen, Parametersemantik, Rückgaben und Fehlerkontrakte | Dokumentationskommentare direkt in `tails-pdp*/src/` |

Die Handbuchquellen liegen im Schwesterverzeichnis der lokalen Ablage. Sie sind für die
Abgabe im vereinbarten `source`-Paket bereitzustellen. Die IDE-Konfiguration „thesis“ ruft
`scripts/build-thesis.sh` auf. Das Skript baut die Thesis und beide Handbücher mit `latexmk`
und kopiert erst nach erfolgreichem Build aller drei Dokumente die PDFs nach `docs/`:

- `Christian_Koch_Attribute_Stream-Based_Access_Control_im_Linux-Kernel.pdf`
- `Christian_Koch_Installationshandbuch_tails-pdp.pdf`
- `Christian_Koch_Programmierhandbuch_tails-pdp.pdf`

Der gemeinsame Build lässt sich aus jeder Arbeitsumgebung mit
`bash scripts/build-thesis.sh` aus der Repository-Wurzel starten. Dazu werden die Quellen
unter `../thesis/` und eine LaTeX-Installation einschließlich `latexmk` und Biber benötigt.
Die PDFs können anschließend in die vereinbarte FTK-Ablage übernommen werden.
Die Handbücher benötigen keine eingebundenen Thesis-Dateien und sind auch einzeln kompilierbar.

## Rustdoc erzeugen

Auf dem vorbereiteten Linux-Zielsystem aus der Repository-Wurzel:

```sh
./scripts/docs.sh
```

Das Skript erzeugt alle acht Bibliotheksreferenzen und bricht bei fehlender öffentlicher
Dokumentation oder kaputten Rustdoc-Symbolverweisen ab. Ergebnis: `target/doc/`.
Für interne Routinen kann zusätzlich `--document-private-items` übergeben werden.

Cargo-Optionen werden weitergereicht, beispielsweise für einen vorbereiteten Cross-Build:

```sh
./scripts/docs.sh --offline --target x86_64-unknown-linux-musl
```

Dann liegt die HTML-Ausgabe unter `target/x86_64-unknown-linux-musl/doc/`.
Buildwerkzeuge und lokale Abhängigkeiten müssen zuvor bereitgestellt sein. Die
Dokumentationserzeugung kann auch den eingebetteten eBPF-Build auslösen. Rustdoc ersetzt
keinen Kernel-Verifier-/Enforcement-Test. Bestehende Compilerwarnungen der generierten
Kerneltypen können vom Buildskript weitergereicht werden; diese Datei wird nicht verändert.

Ausführbare Beispiele der gemeinsamen Policybibliothek prüfen:

```sh
cargo test --locked --doc -p tails-pdp-common --config 'target."cfg(all())".runner="env"'
```

Diese Beispiele benötigen weder BPF-Pins noch Root. Die Runner-Überschreibung verhindert
die im Workspace sonst konfigurierte privilegierte Ausführung normaler Tests.

Die erzeugte HTML-Dokumentation ist ein Buildartefakt. Für die Abgabe die vollständige
`doc/`-Ausgabe einschließlich Ressourcen kopieren; `target/` wird nicht versioniert.

## Grenzen und Nachweise

Bekannte Einschränkungen sind im Programmierhandbuch und in den betreffenden Crate-/API-
Kommentaren beschrieben: eingeschränkter Policyparser, Dateiidentität statt dauerhafter
Pfadbindung, separate Policy-/Attributgenerationen sowie nicht atomarer, nur für
x86_64-Linux implementierter Remote-FD-Entzug. Debug-/Timing-Ausgaben verursachen Messaufwand.

Das [Evaluationsarchiv](../eval-tails-pdp/README.md) belegt den dort protokollierten Stand.
Spätere Bereinigungen und Dokumentationsänderungen sind kein neuer vollständiger
Linux-Systemtestnachweis. Finaler Quellstand, Binaries, Werkzeugumgebung und zugehörige
Tests sind bei der Übergabe eindeutig zuzuordnen.

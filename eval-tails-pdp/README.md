# Evaluationsnachweise für tails-pdp

Dieses versionierbare Archiv enthält die 245 unveränderten Dateien des Prüflaufs
`test-results/20261010T172219Z-QZnscf/`. Es gehört zum Code-Repository und zur Abgabe.
Kapitel 6 der separat abgelegten Thesis wertet diesen Lauf aus.

## Zuordnung

- Protokollierter Code-Commit: `a9fd6c0198e18e22faf3dc6fcf51830ec5bff98b`.
- Der damalige Arbeitsbaum war nicht unverändert: `metadata.txt` und `source.diff`
  dokumentieren den Stand; unversionierte Quelldateien sind nicht im Diff gesichert.
- Testfixtures, Logs, Szenarioreports und Messdaten wurden nicht verändert.
- Spätere Bereinigungen des Codes sind kein neuer Evaluationsnachweis.
- Historische Nachweise bleiben in der separat abgelegten Thesis unter
  `test-results/` und `test-results-2/` erhalten.

## Integritätsprüfung

Im Verzeichnis `eval-tails-pdp/` ausführen:

- Linux: `sha256sum -c SHA256SUMS`
- macOS: `shasum -a 256 -c SHA256SUMS`

## Gemeinsame Abgabe

```text
abgabe/
  tails-pdp/
    eval-tails-pdp/  # dieses Archiv
  thesis/           # Thesis, bearbeitbare Quellen und historische Nachweise
```

Die konkrete Cloud-/source-Ablage richtet sich zusätzlich nach den vereinbarten
FTK- und Prüfungsamtsvorgaben. Laufartefakte zukünftiger Tests werden zunächst unter
`test-results/` erzeugt und können nach Prüfung gezielt in dieses Archiv übernommen werden.

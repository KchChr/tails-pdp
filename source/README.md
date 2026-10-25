# LaTeX-Quellen der Abgabe

Dieser Ordner enthält eine Kopie der Thesis- und Handbuchquellen sowie der verwendeten Bilddateien (Stand: 25. Oktober 2026).

- `Christian_Koch_Attribute_Stream-Based_Access_Control_im_Linux-Kernel.tex`: Hauptdatei der Thesis; Inhalt unverändert aus der ursprünglichen lokalen Hauptdatei `thesis.tex` übernommen.
- `sections/`: Kapitel einschließlich der Vorlage der Selbstständigkeitserklärung.
- `literatur.bib`: Literaturdaten.
- `graphics/`: Bilddateien; `.drawio`-Dateien sind auf Wunsch nicht enthalten.
- `Christian_Koch_Installationshandbuch_tails-pdp.tex` und `Christian_Koch_Programmierhandbuch_tails-pdp.tex`: eigenständige Handbuchquellen.

## PDFs erstellen

Benötigt werden eine passende LaTeX-Installation, `latexmk` und Biber sowie die in den Präambeln verwendeten Pakete. Im Ordner `source/`:

```sh
latexmk -pdf -interaction=nonstopmode -halt-on-error Christian_Koch_Attribute_Stream-Based_Access_Control_im_Linux-Kernel.tex Christian_Koch_Installationshandbuch_tails-pdp.tex Christian_Koch_Programmierhandbuch_tails-pdp.tex
```

Die vorhandenen PDF-Ausgaben liegen im Repository unter `../thesis/final/`. Diese Quellen sind eine Momentaufnahme und werden durch den lokalen Thesis-Build nicht automatisch aktualisiert. LaTeX-Zwischendateien gehören nicht zum Quellenpaket. Ein Scan der unterschriebenen Selbstständigkeitserklärung ist separat für die endgültige Abgabe beizufügen.

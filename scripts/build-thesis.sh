#!/usr/bin/env bash
# Build the thesis and both manuals, then publish the PDFs to the repository.
set -euo pipefail

PROJECT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
THESIS_ROOT="$PROJECT_ROOT/../thesis"
OUTPUT_ROOT="$PROJECT_ROOT/thesis/final"

cd -- "$THESIS_ROOT"
latexmk -pdf -synctex=1 -interaction=nonstopmode -halt-on-error \
    thesis.tex \
    Christian_Koch_Programmierhandbuch_tails-pdp.tex \
    Christian_Koch_Installationshandbuch_tails-pdp.tex

# Do not replace published documents when one of the builds fails or is empty.
for document in thesis Christian_Koch_Programmierhandbuch_tails-pdp Christian_Koch_Installationshandbuch_tails-pdp; do
    test -s "$document.pdf"
done

mkdir -p -- "$OUTPUT_ROOT"
cp -- thesis.pdf "$OUTPUT_ROOT/Christian_Koch_Attribute_Stream-Based_Access_Control_im_Linux-Kernel.pdf"
cp -- Christian_Koch_Programmierhandbuch_tails-pdp.pdf "$OUTPUT_ROOT/"
cp -- Christian_Koch_Installationshandbuch_tails-pdp.pdf "$OUTPUT_ROOT/"
printf 'Thesis und Handbücher wurden nach %s kopiert.\n' "$OUTPUT_ROOT"

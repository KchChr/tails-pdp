#!/usr/bin/env bash
# Redaktionsplan der Demo: Hier wird die Reihenfolge ausdrücklich festgelegt.
# Im Worker einbinden, damit alle Kapitel dieselbe Runtime und Variablen nutzen.
# Die fachlichen Kapitel bauen aufeinander auf; Änderungen entsprechend prüfen.

    source "$PROJECT_ROOT/scripts/demo/cases/00-einfuehrung.sh"
    # Die Fälle verwenden denselben Demo-Zustand und bauen aufeinander auf.
    source "$PROJECT_ROOT/scripts/demo/cases/01-runtime-start.sh"
    source "$PROJECT_ROOT/scripts/demo/cases/02-statische-policies.sh"
    source "$PROJECT_ROOT/scripts/demo/cases/03-policy-lebenszyklus.sh"
    source "$PROJECT_ROOT/scripts/demo/cases/04-systemattribut.sh"
    source "$PROJECT_ROOT/scripts/demo/cases/05-subjekt-und-ressourcenattribute.sh"
    source "$PROJECT_ROOT/scripts/demo/cases/06-ungueltige-updates.sh"
    source "$PROJECT_ROOT/scripts/demo/cases/07-fd-entzug-policy.sh"
    source "$PROJECT_ROOT/scripts/demo/cases/08-fd-entzug-attribut.sh"
    source "$PROJECT_ROOT/scripts/demo/cases/09-fd-entzug-zeitgrenze.sh"
    source "$PROJECT_ROOT/scripts/demo/cases/10-utc-zeitbedingungen.sh"
    source "$PROJECT_ROOT/scripts/demo/cases/99-abschluss.sh"

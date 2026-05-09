# Glossar

## Aya

Rust-Bibliothek für eBPF. Aya lädt eBPF-Programme, öffnet Maps und stellt Makros für eBPF-Programme
bereit.

## BTF

BPF Type Format. Enthält Typinformationen des Kernels. Aya nutzt BTF, um LSM-Programme korrekt zu
laden.

## eBPF

Linux-Technik, mit der kleine, geprüfte Programme im Kernel laufen können.

## eBPF-Map

Gemeinsamer Speicher zwischen Userspace und eBPF-Programm. Vergleichbar mit einer kleinen Tabelle.

## FD

File Descriptor. Eine Zahl, mit der ein Prozess eine geöffnete Datei, einen Socket oder ein anderes
Kernel-Objekt referenziert.

## Inode

Kernel-interne Identität einer Datei innerhalb eines Dateisystems. Zusammen mit dem Device-Wert kann
eine Datei identifiziert werden.

## Kernelspace

Bereich, in dem der Linux-Kernel läuft. Fehler dort sind besonders kritisch.

## LSM

Linux Security Modules. Sicherheits-Framework im Linux-Kernel.

## LSM-Hook

Konkreter Sicherheitsprüfpunkt im Kernel, z. B. `file_open` oder `socket_bind`.

## Map Pinning

Speichern einer eBPF-Map im BPF-Dateisystem, z. B. unter `/sys/fs/bpf/tails-pdp`. Dadurch kann sie
von mehreren Prozessen geöffnet werden.

## PDP

Policy Decision Point. Komponente, die eine Policy auswertet und eine Entscheidung trifft.

## Permit

Policy-Entscheidung, die für Erlauben spricht.

## Deny

Policy-Entscheidung, die für Verweigern spricht.

## Policy

Regel, die beschreibt, welche Aktion unter welchen Bedingungen erlaubt oder verboten ist.

## Policy-Generation

Versionsnummer der aktuell aktiven Policies. Dieses Projekt nutzt sie, um neue Policies zuerst in
eine inaktive Bank zu schreiben und erst danach umzuschalten.

## Ring Buffer

Mechanismus, mit dem eBPF Events an den Userspace senden kann. Dieses Projekt nutzt aktuell keinen
Ring Buffer.

## Rust

Programmiersprache mit Fokus auf Speichersicherheit und Performance.

## SAPL

Policy-Sprache, an deren Struktur sich die `.sapl`-Dateien in diesem Projekt anlehnen. Das Projekt
implementiert aber nur eine kleine, eigene Teilmenge.

## Socket

Kernel-Objekt für Netzwerkkommunikation. Bei `socket_bind` wird ein Socket an eine lokale IP und
einen Port gebunden.

## Stack

Speicherbereich für lokale Variablen einer Funktion. Im eBPF-Kontext ist dieser sehr klein.

## Tail Call

Sprung von einem eBPF-Programm in ein anderes über eine `ProgramArray`-Map. Hilft, große Programme
in kleinere Teile aufzuteilen.

## Userspace

Bereich, in dem normale Programme laufen, z. B. Shell, Loader oder Admin-Tool.

## Verifier

Kernel-Komponente, die eBPF-Programme vor dem Laden prüft. Er verhindert viele unsichere Programme.

## Quellen dieses Kapitels

Dieses Kapitel stützt sich auf die Projektquellen [P1], [P3], [P6], [P7], [P8], [P10], [P12],
[P14] und [P17] sowie auf die externen Quellen [Q1], [Q4], [Q5], [Q7], [Q8], [Q9], [Q10], [Q11],
[Q12], [Q15], [Q17], [Q22] und [Q23]. Die vollständige Quellenliste steht in
[Quellen und Zitierweise](12-quellen.md).

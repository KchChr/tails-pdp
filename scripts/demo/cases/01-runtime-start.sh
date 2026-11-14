#!/usr/bin/env bash
# Kapitel 1: Die Durchsetzung erst nach dem nachgewiesenen LSM-Attach prüfen.
# Der leere Policy-Stand zeigt das Allow-Verhalten ohne passende Deny-Policy.
# Wird in demo_worker eingebunden und nutzt dessen Runtime und Arbeitsbereich.

    chapter '1. Runtime starten und Ausgangszustand prüfen' \
        'Die Dateien sind vorbereitet:
  demo/files/protected.txt – die Datei, deren Zugriff durch Policies geschützt werden soll.
  demo/files/control.txt – eine separate Kontrolldatei, die weiterhin zugänglich bleiben soll.
  demo/files/alias.txt – ein Hardlink auf protected.txt; beide Pfade verweisen auf dieselbe Datei.

  Es läuft noch keine Runtime und es sind keine Policies geladen.' \
        'Der Prototyp wird gestartet. Dabei wird das eBPF-Programm geladen, die Maps werden vorbereitet und der file_open-Hook wird angehängt. Danach wird die geschützte Datei geöffnet.' \
        'Alle erwarteten Maps existieren, die Runtime läuft und die Dateiöffnung ist erlaubt: Ohne passende Deny-Policy wird kein Zugriff untersagt.' \
        'Rechts oben bestätigt die Runtime ihren Start. Deny-Entscheidungen des Kernelspace-PEP erscheinen dort als [Kernelspace-PEP] mit final=deny. USERSPACE_PEP ist die Logkennung des Userspace-PEP. Beide Durchsetzungspfade besitzen eine integrierte PDP-Funktion zur Policy-Auswertung. Links zeigt das Admin-Tool den geladenen Zustand; die anschließende OK-Zeile bestätigt den tatsächlichen Zugriff.'
    start_kernel_trace
    RUST_LOG=info TAILS_PDP_EBPF_DEBUG=deny TAILS_PDP_TIMING=0 "$TAILS_PDP_BIN" >> "$demo_root/runtime.log" 2>&1 &
    runtime_pid=$!
    wait_log 'Waiting for Ctrl-C'
    if ! grep -Fq 'Kernel debug logging mode=Deny' "$demo_root/runtime.log"; then
        fail 'Der reduzierte Kernel-Loggingmodus wurde nicht bestätigt. Bitte die Binaries mit ./scripts/demo.sh --build neu bauen.'
        return 1
    fi
    local name
    for name in POLICY_GENERATION ATTRIBUTE_GENERATION FILE_OPEN_STATIC_POLICIES FILE_OPEN_STREAM_POLICIES CURRENT_TIME ATTRIBUTES; do
        [[ -e "$pin_dir/$name" ]] || { fail "Map fehlt: $name"; return 1; }
    done
    wait_log 'scan completed'
    admin
    access_is allow
    explain 'Ergebnis: Die Runtime ist bereit und der Ausgangszugriff ist erlaubt. Ab jetzt bleibt derselbe Runtime-Prozess aktiv.'

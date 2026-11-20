#!/usr/bin/env bash
# Kapitel 1: Das Enforcement erst nach dem nachgewiesenen LSM-Attach prüfen.
# Der leere Policy-Stand zeigt das Allow-Verhalten ohne passende Deny-Policy.
# Wird in demo_worker eingebunden und nutzt dessen Runtime und Arbeitsbereich.

    chapter_start '1. Runtime starten und Ausgangszustand prüfen'
    chapter_section 'Ausgangslage' \
        "relevante Dateien:
  $target
  $safe
  ${target%/*}/alias.txt

  Es läuft noch keine Runtime und es sind keine Policies geladen."
    chapter_section 'Aktion' \
        "Der Prototyp wird gestartet und die Ressource geöffnet."
    chapter_section 'Erwartetes Verhalten' \
        'Die Datei kann ohne Einschränkungen geöffnet werden, es erfolgt kein Enforcement.'
    printf '\n'
    pause_demo

    start_kernel_trace
    RUST_LOG=info TAILS_PDP_EBPF_DEBUG=deny TAILS_PDP_TIMING=0 "$TAILS_PDP_BIN" >> "$demo_root/runtime.log" 2>&1 &
    runtime_pid=$!
    wait_log 'Waiting for Ctrl-C'
    if ! grep -Fq 'Kernel debug logging mode=Deny' "$demo_root/runtime.log"; then
        fail "Der reduzierte Kernel-Loggingmodus wurde nicht bestätigt. Bitte die Binaries mit $(printf '%q' "$PROJECT_ROOT/scripts/demo.sh") --build neu bauen."
        return 1
    fi
    local name
    for name in POLICY_GENERATION ATTRIBUTE_GENERATION FILE_OPEN_STATIC_POLICIES FILE_OPEN_STREAM_POLICIES CURRENT_TIME ATTRIBUTES; do
        [[ -e "$pin_dir/$name" ]] || { fail "Map fehlt: $name"; return 1; }
    done
    wait_log 'scan completed'
    admin
    command_access_is allow cat -
    explain 'Ergebnis: Die Runtime ist bereit.'

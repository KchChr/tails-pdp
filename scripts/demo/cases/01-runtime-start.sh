#!/usr/bin/env bash
# Kapitel 1: Die Durchsetzung erst nach dem nachgewiesenen LSM-Attach prüfen.
# Der leere Policy-Stand zeigt das Allow-Verhalten ohne passende Deny-Policy.
# Wird in demo_worker eingebunden und nutzt dessen Runtime und Arbeitsbereich.

    chapter '1. Runtime starten und Ausgangszustand prüfen' \
        "relevante Dateien:
  $target
  $safe
  ${target%/*}/alias.txt

  Es läuft noch keine Runtime und es sind keine Policies geladen." \
        "Der Prototyp wird gestartet. Danach wird die Datei ${target} geöffnet." \
                'Die Datei kann ohne Einschränkungen geöffnet werden, es erfolgt noch kein Enforcmement' \
        ''

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
    access_is allow
    explain 'Ergebnis: Die Runtime ist bereit und der Ausgangszugriff ist erlaubt. Ab jetzt bleibt derselbe Runtime-Prozess aktiv.'

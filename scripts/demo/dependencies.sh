#!/usr/bin/env bash
# sudo is a host capability, not a dependency supplied by nix-shell.
resolve_demo_sudo() {
    local candidate system_wrapper="${1:-/run/wrappers/bin/sudo}"
    if [[ -n "${DEMO_SUDO_BIN:-}" ]]; then
        candidate="$DEMO_SUDO_BIN"
    elif [[ -x "$system_wrapper" ]]; then
        candidate="$system_wrapper"
    else
        candidate="$(type -P sudo)" || {
            printf 'System-sudo fehlt. Bitte sudo auf dem Zielsystem einrichten oder als root starten.\n' >&2
            return 1
        }
    fi
    if [[ "$candidate" != /* || ! -x "$candidate" || "$candidate" == /nix/store/* ]]; then
        printf 'Kein verwendbares System-sudo: %s. Benötigt wird der eingerichtete Systemwrapper (NixOS: /run/wrappers/bin/sudo).\n' "$candidate" >&2
        return 1
    fi
    printf '%s\n' "$candidate"
}

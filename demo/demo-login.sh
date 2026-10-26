# Sourced by a Bash login shell. Noninteractive SSH and file transfers are unaffected.
if [[ $- == *i* && -t 0 && -t 1 && ${USER:-} == demo && -n ${SSH_CONNECTION:-} && -z ${TMUX:-} && -z ${PROTOTYPE_DEMO_LOGIN:-} ]]; then
    export PROTOTYPE_DEMO_LOGIN=1
    (
        set -e
        cd /home/demo/tails-pdp
        printf '\nDer Prototyp wird aus den mitgelieferten Offline-Quellen gebaut.\n\n'
        # Build directly with the ISO's system environment; no nix-shell needed.
        bash ./scripts/demo/build.sh
        ./scripts/demo.sh
    ) || printf '\nDie Demo wurde mit einem Fehler beendet. Die Shell bleibt zur Diagnose geöffnet.\n' >&2
fi

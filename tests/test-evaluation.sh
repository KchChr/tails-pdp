#!/usr/bin/env bash
# Runs the per-ID Bash scenarios with isolated runtime fixtures and saved reports.
set -Eeuo pipefail
PROJECT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -z "${TAILS_PDP_TEST_RESULTS_DIR:-}" ]]; then
    exec python3 "$PROJECT_ROOT/tests/evaluation/run.py" "$@"
fi

# Die kurzen /tmp-Pfade der Fixtures bleiben erhalten (Policy-Pfade sind begrenzt).
# Erst nach dem Szenariolauf werden dessen Reports und Rohdaten archiviert.
mkdir -p "$TAILS_PDP_TEST_RESULTS_DIR/evaluation"
if [[ -n "${SUDO_UID:-}" && -n "${SUDO_GID:-}" ]]; then
    chown -- "$SUDO_UID:$SUDO_GID" "$TAILS_PDP_TEST_RESULTS_DIR/evaluation"
fi
EVAL_ARTIFACT_PATH_FILE="$(mktemp "$TAILS_PDP_TEST_RESULTS_DIR/.evaluation-path.XXXXXX")"
export EVAL_ARTIFACT_PATH_FILE
status=0
python3 "$PROJECT_ROOT/tests/evaluation/run.py" "$@" || status=$?
if [[ -s "$EVAL_ARTIFACT_PATH_FILE" ]]; then
    IFS= read -r artifact_root <"$EVAL_ARTIFACT_PATH_FILE"
    archive="$TAILS_PDP_TEST_RESULTS_DIR/evaluation/$(basename -- "$artifact_root")"
    if cp -a -- "$artifact_root" "$archive"; then
        if [[ -n "${SUDO_UID:-}" && -n "${SUDO_GID:-}" ]]; then
            chown -R -- "$SUDO_UID:$SUDO_GID" "$archive" || status=1
        fi
        echo "Archivierte Evaluationsartefakte: $archive"
    else
        echo "Fehler: Evaluationsartefakte konnten nicht archiviert werden: $artifact_root" >&2
        status=1
    fi
fi
rm -f -- "$EVAL_ARTIFACT_PATH_FILE"
exit "$status"

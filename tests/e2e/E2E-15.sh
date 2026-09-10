#!/usr/bin/env bash
# Test-ID: E2E-15
set -Eeuo pipefail
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/../evaluation/shell.sh"
evaluation_scenario E2E-15

# Numeric UIDs avoid creating accounts; effective/filesystem UID stays root.
policy_and_wait test deny 'subject.uid == 60001;'
[[ "$(python3 "$EVAL_HELPERS/access.py" "$TARGET_FILE" 60001)" == deny ]] || fail "Real UID 60001 nicht verweigert"
[[ "$(python3 "$EVAL_HELPERS/access.py" "$TARGET_FILE" 60002)" == allow ]] || fail "Negativkontrolle 60002 nicht erlaubt"

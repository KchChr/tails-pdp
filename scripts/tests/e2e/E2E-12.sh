#!/usr/bin/env bash
# Test-ID: E2E-12
set -Eeuo pipefail
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/../evaluation/shell.sh"
evaluation_scenario E2E-12

subject="subjects/$(id -u).attributes"
resource="resources${TARGET_FILE}.attributes"
attribute_and_wait system.attributes 'defcon = 2'
attribute_and_wait "$subject" 'position = "engineer"'
attribute_and_wait "$resource" 'classification = "internal"'
policy_and_wait test deny $'system.defcon <= 2;\nsubject.position == "engineer";\nresource.classification == "internal";'
expect_access deny
# Each conjunct must independently affect the decision, including missing/type errors.
paths=(system.attributes "$subject" "$resource" "$subject" "$subject")
bad=('defcon = 5' 'position = "intern"' 'classification = "public"' 'position = 1' '# missing attribute')
good=('defcon = 2' 'position = "engineer"' 'classification = "internal"' 'position = "engineer"' 'position = "engineer"')
for i in "${!paths[@]}"; do
    attribute_and_wait "${paths[i]}" "${bad[i]}"
    expect_access allow
    attribute_and_wait "${paths[i]}" "${good[i]}"
    expect_access deny
done

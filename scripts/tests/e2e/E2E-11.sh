#!/usr/bin/env bash
# Test-ID: E2E-11
set -Eeuo pipefail
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/../evaluation/shell.sh"
evaluation_scenario E2E-11

policy_and_wait permit permit
expect_access allow
policy_and_wait deny deny
expect_access deny
remove_policy_and_wait deny
expect_access allow
# Reverse lexical policy order: Deny must still override Permit.
policy_and_wait aaa-deny deny
expect_access deny

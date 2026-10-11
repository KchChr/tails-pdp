#!/usr/bin/env bash

set -euo pipefail

readonly PROJECT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd -- "$PROJECT_ROOT"

cargo build --locked --bin tails-pdp-admintool --release
exec cargo run --locked --bin tails-pdp --release

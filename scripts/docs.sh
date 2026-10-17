#!/usr/bin/env bash

# Generate the workspace API reference; forward Cargo options such as --target.
set -euo pipefail
readonly PROJECT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd -- "$PROJECT_ROOT"

export RUSTDOCFLAGS="${RUSTDOCFLAGS:-} -D missing_docs -D rustdoc::broken_intra_doc_links"
exec cargo doc --locked --no-deps --workspace --lib "$@"

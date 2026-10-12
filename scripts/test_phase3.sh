#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
cargo fmt --check
cargo check
cargo test
python3 tests/integration_http.py "$@"

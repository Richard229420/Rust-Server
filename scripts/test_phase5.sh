#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
cargo fmt --check
cargo check
cargo test
cargo build --release
# Scripts iniciam sua propria instancia; a porta 8080 deve estar livre.
python3 tests/integration_http.py --stress
python3 tests/security_http.py
python3 tests/api_rest.py

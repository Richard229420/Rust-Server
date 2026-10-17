#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo '[FASE 6.1] Testes do contrato SQLite'
python3 tests/auth61_schema_contract.py

echo '[FASE 6.1] Rust: formatacao, compilacao, unitarios e Clippy rigoroso'
cargo fmt --check
cargo check
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --release

echo '[FASE 6.1] Identidades SQLite isoladas (porta 8080 livre)'
python3 tests/auth61_integration.py

if [[ "${1:-}" == '--full' ]]; then
  echo '[FASE 6.1] Regressao anterior com bancos temporarios'
  TMP_DB_DIR="$(mktemp -d -t rust-auth61-regress-XXXXXX)"
  trap 'rm -rf -- "$TMP_DB_DIR"' EXIT
  export RUST_SERVER_DB_PATH="$TMP_DB_DIR/users.sqlite3"
  unset RUST_SERVER_AUTH_DB_PATH
  bash scripts/test_fase54.sh --full
fi
printf '[OK] Fase 6.1 validada nos cenarios executados.\n'

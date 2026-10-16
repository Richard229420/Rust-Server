#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo '[FASE 5.3] Validando OpenAPI YAML / JSON e contrato Rust...'
python3 scripts/validate_openapi.py --sources
python3 tests/openapi_contract.py
if [[ "${1:-}" == '--full' ]]; then
  echo '[FASE 5.3] Regressao completa Rust, SQLite, HTTP, seguranca e REST.'
  echo '[INFO] Antes de prosseguir: porta 8080 livre e nenhuma instancia cargo run.'
  DB_DIR="$(mktemp -d -t fase53-tests-XXXXXX)"
  trap 'rm -rf -- "$DB_DIR"' EXIT
  export RUST_SERVER_DB_PATH="$DB_DIR/users.sqlite3"
  cargo fmt --check
  cargo check
  cargo test
  cargo clippy --all-targets -- -D warnings
  cargo build --release
  python3 tests/sqlite_persistence.py
  python3 tests/integration_http.py --stress
  python3 tests/security_http.py
  # Usar banco temporario: o script api_rest.py escreve dados de teste.
  python3 tests/api_rest.py
  echo '[OK] Regressao completa Fase 5.3 aprovada.'
fi

echo '[OK] Refinamento 5.3: OpenAPI 3.1.1 validado.'

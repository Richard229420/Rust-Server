#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
python3 scripts/validate_openapi.py --sources
python3 tests/openapi_contract.py
python3 tests/ui54_test.py
if [[ "${1:-}" == '--full' ]]; then
  echo '[FASE 5.4] Regressao completa (porta 8080 deve estar livre).'
  cargo fmt --check
  cargo check
  cargo test
  cargo clippy --all-targets -- -D warnings
  cargo build --release
  python3 tests/sqlite_persistence.py
  python3 tests/integration_http.py --stress
  python3 tests/security_http.py
  python3 tests/api_rest.py
fi
printf '[OK] Validacao Fase 5.4 concluida.\n'

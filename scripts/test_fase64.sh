#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
printf '[FASE 6.4] Rust: formatacao, build, unitarios, Clippy rigoroso e release\n'
cargo fmt --check
cargo check --all-targets
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
cargo build --release --bins
printf '[FASE 6.4] Integracao de auditoria, limites, RBAC e metricas (SQLite temporario)\n'
python3 tests/auth64_integration.py
printf '[FASE 6.4] Regressao RBAC 6.3 (SQLite temporario)\n'
python3 tests/auth63_rbac_integration.py
printf '[FASE 6.4] Swagger Lab e OpenAPI 6.3\n'
python3 tests/auth64_openapi_contract.py
python3 tests/ui54_test.py
python3 tests/ui63_security.py
printf '[FASE 6.4] SQLite esquema de identidades 6.1\n'
python3 tests/auth61_schema_contract.py
printf '[OK] Fase 6.4 passou nas verificacoes executadas.\n'
if [[ "${1:-}" == '--full' ]]; then
  printf '[INFO] Antigas suites REST anonimas foram substituidas pelo contrato RBAC 6.3.\n'
  printf '[INFO] Limites na memoria reiniciam com o processo; persistencia de bloqueios e melhoria futura.\n'
fi

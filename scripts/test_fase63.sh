#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
printf '[FASE 6.3] Rust: formatacao, compilacao, testes, Clippy e release\n'
cargo fmt --check
cargo check --all-targets
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
cargo build --release --bins
printf '[FASE 6.3] RBAC fim-a-fim (bancos temporarios)\n'
python3 tests/auth63_rbac_integration.py
printf '[FASE 6.3] Contrato OpenAPI atualizado\n'
python3 tests/auth63_openapi_contract.py
printf '[FASE 6.3] Regressao do proxy Swagger Lab (backend simulado)\n'
python3 tests/ui54_test.py
python3 tests/ui63_security.py
printf '[FASE 6.3] SQLite de autenticacao 6.1 (esquema isolado)\n'
python3 tests/auth61_schema_contract.py
printf '[OK] Fase 6.3 passou nas verificacoes executadas.\n'
if [[ "${1:-}" == '--full' ]]; then
  printf '[INFO] Suítes CRUD antigas pressupõem acesso anônimo e não são executadas: contrato mudou na 6.3.\n'
  printf '[INFO] A suíte auth63 cobre GET/POST/PUT/PATCH/DELETE, RBAC, erros e persistência em bancos temporários.\n'
fi

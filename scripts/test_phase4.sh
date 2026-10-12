#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

echo '[1/5] cargo fmt --check'
cargo fmt --check
echo '[2/5] cargo check'
cargo check
echo '[3/5] cargo test'
cargo test
echo '[4/5] 17 testes anteriores com sobrecarga'
python3 tests/integration_http.py --stress
echo '[5/5] testes novos de seguranca HTTP'
python3 tests/security_http.py
printf '\n[OK] Fase 4 Rust e HTTP validada. HTTPS: execute tests/https_tls.py depois de iniciar Caddy.\n'

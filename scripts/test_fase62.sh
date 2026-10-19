#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
printf '[FASE 6.2] Rust: formatacao, compilacao, unitarios, Clippy e release\n'
cargo fmt --check
cargo check --all-targets
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
cargo build --release --bins
printf '[FASE 6.2] Endpoints e sessoes (somente bancos temporarios)\n'
python3 tests/auth62_integration.py
if [[ "${1:-}" == '--full' ]]; then
  printf '[FASE 6.2] Regressao Fases 6.1 e 5.4\n'
  bash scripts/test_fase61.sh --full
fi
printf '[OK] Fase 6.2 validada nos cenarios executados.\n'

#!/usr/bin/env bash
# Regressao de ACL TCP/TLS. Nao altera tokens nem certificados.
set -euo pipefail
cd "$(dirname "$0")/.."
: "${RUST_SERVER_BUS_TOKEN:?source scripts/env_phase8.sh}"
: "${RUST_SERVER_BUS_READ_TOKEN:?source scripts/env_phase8.sh}"
: "${RUST_SERVER_BUS_WRITE_TOKEN:?source scripts/env_phase8.sh}"
for binary in cargo rg timeout ss; do command -v "$binary" >/dev/null || { echo "Dependencia ausente: $binary" >&2; exit 1; }; done

if ! ss -lnt | rg -q '127\.0\.0\.1:7001\b'; then
  echo 'ERRO: inicie o servidor multiprotocolo na porta 7001 antes dos testes.' >&2
  exit 1
fi

TEMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TEMP_DIR"' EXIT

echo '[1/5] Token de leitura nao pode publicar.'
RUST_SERVER_BUS_WRITE_TOKEN="$RUST_SERVER_BUS_READ_TOKEN" \
  timeout 8 cargo run --quiet --example bus_client -- tcp-pub alerts negado-reader \
  >"$TEMP_DIR/reader-pub" 2>&1
rg -q '^ERR acesso negado$' "$TEMP_DIR/reader-pub" || { cat "$TEMP_DIR/reader-pub"; exit 1; }
if rg -q '^OK PUB' "$TEMP_DIR/reader-pub"; then echo 'FALHA: leitura publicou' >&2; exit 1; fi

echo '[2/5] Token de escrita nao pode assinar.'
# tcp-sub fica conectado por design; timeout encerra o teste apos receber ERR acesso negado.
RUST_SERVER_BUS_READ_TOKEN="$RUST_SERVER_BUS_WRITE_TOKEN" \
  timeout 4 cargo run --quiet --example bus_client -- tcp-sub alerts \
  >"$TEMP_DIR/writer-sub" 2>&1 || true
rg -q '^ERR acesso negado$' "$TEMP_DIR/writer-sub" || { cat "$TEMP_DIR/writer-sub"; exit 1; }
if rg -q '^OK SUB$' "$TEMP_DIR/writer-sub"; then echo 'FALHA: escrita assinou' >&2; exit 1; fi

echo '[3/5] Token de escrita nao pode publicar em admin/secret.'
timeout 8 cargo run --quiet --example bus_client -- tcp-pub admin/secret negado-writer \
  >"$TEMP_DIR/writer-admin" 2>&1
rg -q '^ERR acesso negado$' "$TEMP_DIR/writer-admin" || { cat "$TEMP_DIR/writer-admin"; exit 1; }
if rg -q '^OK PUB' "$TEMP_DIR/writer-admin"; then echo 'FALHA: topico administrativo publicado' >&2; exit 1; fi

echo '[4/5] Token incorreto nao pode autenticar.'
RUST_SERVER_BUS_WRITE_TOKEN='token-invalido-proposital-0123456789' \
  timeout 8 cargo run --quiet --example bus_client -- tcp-pub alerts negado-auth \
  >"$TEMP_DIR/bad-auth" 2>&1
rg -q '^ERR autenticacao$' "$TEMP_DIR/bad-auth" || { cat "$TEMP_DIR/bad-auth"; exit 1; }
if rg -q '^OK AUTH$|^OK PUB' "$TEMP_DIR/bad-auth"; then echo 'FALHA: credencial invalida aceita' >&2; exit 1; fi

echo '[5/5] Escrita permitida em alerts.'
timeout 8 cargo run --quiet --example bus_client -- tcp-pub alerts validacao-acl-tcp \
  >"$TEMP_DIR/valid-pub" 2>&1
rg -q '^OK PUB [0-9]+' "$TEMP_DIR/valid-pub" || { cat "$TEMP_DIR/valid-pub"; exit 1; }
echo 'APROVADO: controles negativos TCP/TLS e publicacao autorizada.'
echo 'OBS: limites de assinaturas e comandos sao cobertos pelos testes unitarios em src/messaging.rs.'

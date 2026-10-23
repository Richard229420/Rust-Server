#!/usr/bin/env bash
# Testa credenciais MQTT com controle positivo; sem presumir que falha TLS e falha de autenticacao sejam iguais.
set -euo pipefail
cd "$(dirname "$0")/.."
: "${RUST_SERVER_MQTT_LAB_PASSWORD:?source scripts/env_phase8.sh}"
for binary in mosquitto_pub openssl timeout rg; do
  command -v "$binary" >/dev/null || { echo "Dependencia ausente: $binary" >&2; exit 1; }
done
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo '[1/3] Validacao TLS contra CA local...'
(timeout 8 openssl s_client -connect 127.0.0.1:8883 -servername localhost \
  -CAfile certs/ca.crt -verify_return_error -brief </dev/null) >"$TMP/tls" 2>&1 || {
  cat "$TMP/tls"; exit 1;
}
rg -q 'Verification: OK' "$TMP/tls" || { cat "$TMP/tls"; exit 1; }

echo '[2/3] Autenticacao correta MQTT 3.1.1...'
timeout 8 mosquitto_pub -d -V mqttv311 -i "fase81-certo-$$" \
  -h localhost -p 8883 --cafile certs/ca.crt \
  -u lab -P "$RUST_SERVER_MQTT_LAB_PASSWORD" \
  -t lab/alerts -m fase81-auth-ok >"$TMP/good" 2>&1 || {
  cat "$TMP/good"; echo 'FALHA: usuario valido nao conseguiu conectar' >&2; exit 1;
}
rg -q 'received CONNACK \(0\)' "$TMP/good" || { cat "$TMP/good"; exit 1; }

echo '[3/3] Senha incorreta deve impedir CONNACK 0...'
if timeout 8 mosquitto_pub -d -V mqttv311 -i "fase81-errado-$$" \
  -h localhost -p 8883 --cafile certs/ca.crt \
  -u lab -P 'senha-invalida-proposital' \
  -t lab/alerts -m fase81-nao-entregar >"$TMP/bad" 2>&1; then
  echo 'FALHA: senha invalida teve sucesso de publicacao MQTT.' >&2
  exit 1
fi
if rg -q 'received CONNACK \(0\)' "$TMP/bad"; then
  echo 'FALHA: broker aceitou autenticar cliente com senha invalida.' >&2
  exit 1
fi
echo 'APROVADO: TLS verificado, login valido aceito e login invalido recusado.'
echo 'Confirme no log do servidor: [MQTT-AUTH] classe=lab resultado=NEGADO (log amostrado).'

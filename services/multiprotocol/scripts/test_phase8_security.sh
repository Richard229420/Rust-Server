#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
: "${RUST_SERVER_MQTT_LAB_PASSWORD:?Execute source scripts/env_phase8.sh}"
: "${RUST_SERVER_BUS_READ_TOKEN:?Execute source scripts/env_phase8.sh}"
: "${RUST_SERVER_BUS_WRITE_TOKEN:?Execute source scripts/env_phase8.sh}"
for bin in cargo mosquitto_pub mosquitto_sub curl rg timeout; do
  command -v "$bin" >/dev/null || { echo "Faltando: $bin" >&2; exit 1; }
done
CERT=certs/ca.crt
TMP="$(mktemp -d)"
SUB_PID=''
cleanup() {
  if [[ -n "$SUB_PID" ]]; then kill "$SUB_PID" 2>/dev/null || true; wait "$SUB_PID" 2>/dev/null || true; fi
  rm -rf "$TMP"
}
trap cleanup EXIT

echo '[1/7] Verificar portas seguras em escuta (HTTP original exigido no teste)...'
ss -lntup | rg ':8883\b' | rg '127\.0\.0\.1'
ss -lntup | rg ':7001\b' | rg '127\.0\.0\.1'
if ss -lntup | rg -q ':1883\b|:7002\b'; then
  echo 'ERRO: MQTT plaintext :1883 ou UDP legado :7002 ativo! Desative antes de validar o padrao seguro.' >&2
  exit 1
fi

echo '[2/7] HTTPS original preservado...'
if ! curl --silent --show-error --fail http://127.0.0.1:8080/ >/dev/null; then
  echo 'ERRO: backend HTTP parado. Em outro terminal: cd ~/server && cargo run' >&2
  exit 1
fi
curl --silent --show-error --fail --cacert "$CERT" https://localhost:8443/ >/dev/null

echo '[3/7] MQTT anonimo NEGADO em TLS...'
if timeout 8 mosquitto_pub -h localhost -p 8883 --cafile "$CERT" -t lab/alerts -m anonimo >"$TMP/anon.out" 2>&1; then
  echo 'ERRO: MQTT aceitou cliente anonimo!' >&2; exit 1
fi

echo '[4/7] MQTT senha incorreta NEGADA em TLS...'
if timeout 8 mosquitto_pub -h localhost -p 8883 --cafile "$CERT" -u lab -P invalida -t lab/alerts -m invalida >"$TMP/bad.out" 2>&1; then
  echo 'ERRO: MQTT aceitou senha errada!' >&2; exit 1
fi

echo '[5/7] MQTT -> TCP-TLS...'
cargo run --quiet --example bus_client -- tcp-sub alerts >"$TMP/tcp.out" 2>&1 &
SUB_PID=$!
sleep 2
mosquitto_pub -h localhost -p 8883 --cafile "$CERT" -u lab -P "$RUST_SERVER_MQTT_LAB_PASSWORD" -t lab/alerts -m fase8-mqtt-to-tcp
for attempt in 1 2 3 4 5 6 7 8 9 10; do
  if rg -q 'MSG alerts fase8-mqtt-to-tcp' "$TMP/tcp.out"; then break; fi
  sleep 1
done
rg -q 'MSG alerts fase8-mqtt-to-tcp' "$TMP/tcp.out" || { cat "$TMP/tcp.out"; echo 'Falha MQTT -> TCP' >&2; exit 1; }
kill "$SUB_PID" 2>/dev/null || true
wait "$SUB_PID" 2>/dev/null || true
SUB_PID=''

echo '[6/7] ACL TCP: token de leitura nao pode publicar...'
RUST_SERVER_BUS_WRITE_TOKEN="$RUST_SERVER_BUS_READ_TOKEN" cargo run --quiet --example bus_client -- tcp-pub alerts proibido >"$TMP/acl.out" 2>&1
rg -q 'ERR acesso negado' "$TMP/acl.out" || { cat "$TMP/acl.out"; echo 'ACL TCP falhou' >&2; exit 1; }

echo '[7/7] TCP-TLS -> MQTT seguro...'
(timeout 9 mosquitto_sub -h localhost -p 8883 --cafile "$CERT" -u lab -P "$RUST_SERVER_MQTT_LAB_PASSWORD" -C 1 -W 8 -t bus/alerts >"$TMP/mqtt.out" 2>&1) &
SUB_PID=$!
sleep 2
cargo run --quiet --example bus_client -- tcp-pub alerts fase8-tcp-to-mqtt >"$TMP/tcp-pub.out" 2>&1
wait "$SUB_PID"
SUB_PID=''
rg -q 'fase8-tcp-to-mqtt' "$TMP/mqtt.out" || { cat "$TMP/mqtt.out"; echo 'Falha TCP -> MQTT' >&2; exit 1; }
echo 'OK: MQTT/TCP criptografados, logins negativos, ACL e bridge nos dois sentidos.'

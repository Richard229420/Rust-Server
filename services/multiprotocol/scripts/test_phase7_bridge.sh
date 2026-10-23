#!/usr/bin/env bash
# Validacao end-to-end: requer HTTP original e multiprotocol em execucao.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
command -v mosquitto_pub >/dev/null || { echo 'Falta mosquitto_pub' >&2; exit 1; }
command -v mosquitto_sub >/dev/null || { echo 'Falta mosquitto_sub' >&2; exit 1; }
command -v timeout >/dev/null || { echo 'Falta timeout (coreutils)' >&2; exit 1; }
: "${RUST_SERVER_BUS_TOKEN:=$(cat "$HOME/.config/rust-server/bus.token")}" 
export RUST_SERVER_BUS_TOKEN
TMP="$(mktemp -d)"
subscriber_pid=""
mqtt_pid=""
cleanup() {
  [[ -z "$subscriber_pid" ]] || kill "$subscriber_pid" 2>/dev/null || true
  [[ -z "$mqtt_pid" ]] || kill "$mqtt_pid" 2>/dev/null || true
  wait 2>/dev/null || true
  rm -rf -- "$TMP"
}
trap cleanup EXIT
wait_for() {
  local expected="$1" file="$2"
  for _ in {1..40}; do
    if grep -Fq -- "$expected" "$file"; then return 0; fi
    sleep 0.2
  done
  echo "[FALHA] Nao apareceu '$expected' em $file" >&2
  cat "$file" >&2
  return 1
}
# Evita recompilar dois exemplos em paralelo, prepara binario de exemplo.
cargo build --example bus_client
BIN="./target/debug/examples/bus_client"
timeout 20 "$BIN" tcp-sub alerts >"$TMP/tcp.log" 2>&1 &
subscriber_pid=$!
wait_for 'OK SUB' "$TMP/tcp.log"
mosquitto_pub -h 127.0.0.1 -p 1883 -t lab/alerts -m 'fase7-mqtt-entrada'
wait_for 'MSG alerts fase7-mqtt-entrada' "$TMP/tcp.log"
echo '[OK] MQTT lab/alerts -> TCP alerts'
timeout 20 mosquitto_sub -h 127.0.0.1 -p 1883 -t bus/alerts -C 2 >"$TMP/mqtt.log" 2>&1 &
mqtt_pid=$!
sleep 0.5
"$BIN" tcp-pub alerts fase7-tcp-saida >"$TMP/pubtcp.log" 2>&1
"$BIN" udp-pub alerts fase7-udp-saida >"$TMP/pubudp.log" 2>&1
wait_for 'fase7-tcp-saida' "$TMP/mqtt.log"
wait_for 'fase7-udp-saida' "$TMP/mqtt.log"
echo '[OK] TCP/UDP alerts -> MQTT bus/alerts'
echo '[OK] Bridge funcionando nos dois sentidos'

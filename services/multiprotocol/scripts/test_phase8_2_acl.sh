#!/usr/bin/env bash
# ACL comprovada no PLANO DE DADOS: SUBACK isoladamente não é critério.
set -euo pipefail
cd "$(dirname "$0")/.."
: "${RUST_SERVER_MQTT_LAB_PASSWORD:?source scripts/env_phase8.sh}"
: "${RUST_SERVER_MQTT_BRIDGE_PASSWORD:?source scripts/env_phase8.sh}"
for bin in mosquitto_pub mosquitto_sub timeout stdbuf rg openssl ss; do
  command -v "$bin" >/dev/null || { echo "Faltando: $bin" >&2; exit 1; }
done
TMP="$(mktemp -d)"
subpid=''
cleanup() {
  if [[ -n "$subpid" ]]; then kill "$subpid" 2>/dev/null || true; wait "$subpid" 2>/dev/null || true; fi
  rm -rf "$TMP"
}
trap cleanup EXIT
unique="acl82-$$-$(date +%s)"
common=(-V mqttv311 -h localhost -p 8883 --cafile certs/ca.crt)

start_sub() {
  local user="$1" pass="$2" topic="$3" output="$4" tag="$5"
  # stdout/stderr em linhas: sem isso o SUBACK pode ficar retido em buffer.
  timeout 15 stdbuf -oL -eL mosquitto_sub -d "${common[@]}" -i "${tag}-$$" -u "$user" -P "$pass" -t "$topic" -v >"$output" 2>&1 &
  subpid=$!
  local i
  for i in {1..80}; do
    if rg -q 'received SUBACK|Subscribed \(mid:' "$output"; then
      rg -q 'received CONNACK \(0\)' "$output" || { cat "$output"; echo 'FALHA: SUBACK sem autenticação bem-sucedida' >&2; exit 1; }
      return 0
    fi
    if ! kill -0 "$subpid" 2>/dev/null; then break; fi
    sleep 0.1
  done
  cat "$output"
  echo 'INCONCLUSIVO: não houve SUBACK visível em até 8 s; confira CONNACK e logs do broker' >&2
  exit 1
}
stop_sub() {
  if [[ -n "$subpid" ]]; then kill "$subpid" 2>/dev/null || true; wait "$subpid" 2>/dev/null || true; subpid=''; fi
}
pub() {
  local user="$1" pass="$2" topic="$3" msg="$4"
  timeout 6 mosquitto_pub "${common[@]}" -i "pub-$unique" -u "$user" -P "$pass" -q 1 -t "$topic" -m "$msg"
}
wait_for() {
  local filename="$1" needle="$2" i
  for i in {1..80}; do
    rg -F -q "$needle" "$filename" && return 0
    sleep 0.1
  done
  return 1
}

printf '[1/7] TLS e portas seguras...\n'
if ss -lnt | rg -q ':1883\b'; then echo 'FALHA: porta MQTT sem TLS 1883 aberta' >&2; exit 1; fi
ss -lnt | rg ':8883\b' | rg -q '127\.0\.0\.1'
openssl verify -CAfile certs/ca.crt -purpose sslserver certs/localhost.crt >/dev/null
printf '[2/7] Login inválido deve falhar...\n'
if timeout 6 mosquitto_pub "${common[@]}" -i "bad-$unique" -u lab -P senha-falsa -t lab/alerts -m negado >"$TMP/invalid" 2>&1; then
  echo 'FALHA: credencial inválida aceita' >&2; exit 1
fi
printf '[3/7] Leitura autorizada bridge em lab/alerts...\n'
start_sub bridge "$RUST_SERVER_MQTT_BRIDGE_PASSWORD" lab/alerts "$TMP/allowed-bridge" goodbridge
pub lab "$RUST_SERVER_MQTT_LAB_PASSWORD" lab/alerts "$unique-read-bridge"
wait_for "$TMP/allowed-bridge" "$unique-read-bridge" || { cat "$TMP/allowed-bridge"; echo 'FALHA: leitura autorizada bridge' >&2; exit 1; }
stop_sub
printf '[4/7] Leitura autorizada lab em bus/alerts...\n'
start_sub lab "$RUST_SERVER_MQTT_LAB_PASSWORD" bus/alerts "$TMP/allowed-lab" goodlab
pub bridge "$RUST_SERVER_MQTT_BRIDGE_PASSWORD" bus/alerts "$unique-read-lab"
wait_for "$TMP/allowed-lab" "$unique-read-lab" || { cat "$TMP/allowed-lab"; echo 'FALHA: leitura autorizada lab' >&2; exit 1; }
stop_sub
printf '[5/7] Leitura PROIBIDA lab em lab/alerts...\n'
start_sub lab "$RUST_SERVER_MQTT_LAB_PASSWORD" lab/alerts "$TMP/no-read" noread
# SUBACK concedido não representa ACL de entrega. Publicação em lab/alerts é autorizada para lab.
pub lab "$RUST_SERVER_MQTT_LAB_PASSWORD" lab/alerts "$unique-no-read"
sleep 2
if rg -F -q "$unique-no-read" "$TMP/no-read"; then cat "$TMP/no-read"; echo 'FALHA: leitura não autorizada entregue!' >&2; exit 1; fi
stop_sub
printf '[6/7] Escrita PROIBIDA lab em bus/alerts...\n'
start_sub lab "$RUST_SERVER_MQTT_LAB_PASSWORD" bus/alerts "$TMP/no-write" nowrite
# QoS 1 permite resposta de erro do broker; mesmo que CLI retorne 0, verificamos ausência real.
pub lab "$RUST_SERVER_MQTT_LAB_PASSWORD" bus/alerts "$unique-no-write" >"$TMP/bad-pub" 2>&1 || true
sleep 2
if rg -F -q "$unique-no-write" "$TMP/no-write"; then cat "$TMP/no-write"; echo 'FALHA: escrita não autorizada foi entregue!' >&2; exit 1; fi
stop_sub
printf '[7/7] Escrita PROIBIDA lab em internal/... e ausência de entrega...\n'
start_sub lab "$RUST_SERVER_MQTT_LAB_PASSWORD" internal/fase8-acl-probe "$TMP/internal" internal
pub lab "$RUST_SERVER_MQTT_LAB_PASSWORD" internal/fase8-acl-probe "$unique-internal" >"$TMP/bad-internal-pub" 2>&1 || true
sleep 2
if rg -F -q "$unique-internal" "$TMP/internal"; then cat "$TMP/internal"; echo 'FALHA: internal entregou mensagem para lab!' >&2; exit 1; fi
stop_sub
printf 'APROVADO: positivos e negativos de leitura/escrita MQTT (entrega real verificada).\n'
printf 'Nota: esta auditoria não prova ausência de outras vulnerabilidades nem protege outros usuários locais.\n'

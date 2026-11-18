#!/usr/bin/env bash
# Integracao real (sem flood): isolamento de dois sensores e revogacao opcional.
set -euo pipefail
umask 077
cd "$(dirname "$0")/.."
if [[ "${1:-}" == '--revoked' ]]; then
  MODE='revoked'; FIRST="${2:-}"; SECOND="${3:-}"
else
  MODE='active'; FIRST="${1:-}"; SECOND="${2:-}"
fi
[[ "$FIRST" =~ ^[a-z][a-z0-9-]{2,31}$ && "$SECOND" =~ ^[a-z][a-z0-9-]{2,31}$ && "$FIRST" != "$SECOND" ]] || {
  echo 'Uso: bash scripts/test_phase8_3_devices.sh sensor01 sensor02' >&2
  echo 'ou:  bash scripts/test_phase8_3_devices.sh --revoked sensor01 sensor02' >&2
  exit 1
}
for bin in mosquitto_sub mosquitto_pub timeout stdbuf rg mktemp ss python3; do
  command -v "$bin" >/dev/null || { echo "Dependencia ausente: $bin" >&2; exit 1; }
done
: "${RUST_SERVER_MQTT_BRIDGE_PASSWORD:?Execute source scripts/env_phase8.sh antes do teste}"
ROOT="$HOME/.config/rust-server"
# Fail closed: rejeita testes feitos antes de aplicar revoke no inventario.
python3 - "$ROOT/mosquitto/devices.json" "$MODE" "$FIRST" "$SECOND" <<'PY'
import json
import pathlib
import sys
inventory, mode, first, second = sys.argv[1:]
try:
    devices = json.loads(pathlib.Path(inventory).read_text(encoding="utf-8"))["devices"]
    expected_first = "revoked" if mode == "revoked" else "active"
    for ident, expected in ((first, expected_first), (second, "active")):
        actual = devices.get(ident, {}).get("state")
        if actual != expected:
            sys.exit(f"PRECONDICAO NAO ATENDIDA: {ident} deve estar {expected}; estado atual={actual!r}. "
                     "Nao execute o teste antes da alteracao no gerenciador.")
except (OSError, ValueError, KeyError, AttributeError, TypeError) as exc:
    sys.exit(f"Nao foi possivel validar o inventario de dispositivos: {exc}")
PY
FIRST_FILE="$ROOT/device-tokens/$FIRST.token"
SECOND_FILE="$ROOT/device-tokens/$SECOND.token"
[[ -r "$SECOND_FILE" ]] || { echo "Token de $SECOND ausente" >&2; exit 1; }
if [[ "$MODE" == 'active' ]]; then
  [[ -r "$FIRST_FILE" ]] || { echo "Token de $FIRST ausente" >&2; exit 1; }
fi
[[ -d /dev/shm && -w /dev/shm ]] || { echo 'Requer /dev/shm para confs temporarias contendo credenciais' >&2; exit 1; }
TMP="$(mktemp -d /dev/shm/mqtt-phase83-test.XXXXXXXX)"
subpid=''
cleanup() {
  if [[ -n "$subpid" ]]; then kill "$subpid" 2>/dev/null || true; wait "$subpid" 2>/dev/null || true; fi
  rm -rf "$TMP"
}
trap cleanup EXIT
# Arquivo -o (Mosquitto 2.1) evita expor senha em /proc/*/cmdline.
client_config() {
  local label="$1" user="$2" secret="$3"
  cat > "$TMP/$label.cfg" <<EOF
-V mqttv311
-h localhost
-p 8883
--cafile $PWD/certs/ca.crt
-u $user
-P $secret
EOF
  chmod 600 "$TMP/$label.cfg"
}
client_config bridge bridge "$RUST_SERVER_MQTT_BRIDGE_PASSWORD"
: "${RUST_SERVER_MQTT_LAB_PASSWORD:?Carregue credenciais de lab com source scripts/env_phase8.sh}"
client_config lab lab "$RUST_SERVER_MQTT_LAB_PASSWORD"
client_config second "device-$SECOND" "$(tr -d '\r\n' < "$SECOND_FILE")"
if [[ "$MODE" == 'active' ]]; then
  client_config first "device-$FIRST" "$(tr -d '\r\n' < "$FIRST_FILE")"
else
  # Nao usar token revogado aqui: a ausencia no banco ja e checada no CLI e tentativas
  # de login com senha antiga serao testadas separadamente (arquivo privado opcional).
  if [[ -r "${RUST_SERVER_REVOKED_TOKEN_FILE:-/arquivo-inexistente}" ]]; then
    client_config first "device-$FIRST" "$(tr -d '\r\n' < "$RUST_SERVER_REVOKED_TOKEN_FILE")"
  fi
fi
unique="phase83-$$-$(date +%s)"
start_sub() {
  local label="$1" topic="$2" output="$3"
  timeout 14 stdbuf -oL -eL mosquitto_sub -d -o "$TMP/$label.cfg" -i "$label-$unique" -t "$topic" -v > "$output" 2>&1 &
  subpid=$!
  local i
  for i in {1..80}; do
    if rg -q 'received SUBACK|Subscribed \(mid:' "$output"; then
      rg -q 'received CONNACK \(0\)' "$output" || { cat "$output"; echo 'FALHA: SUBACK sem CONNACK aceito' >&2; exit 1; }
      return
    fi
    if ! kill -0 "$subpid" 2>/dev/null; then break; fi
    sleep 0.1
  done
  cat "$output"; echo "INCONCLUSIVO: sem SUBACK no tempo esperado" >&2; exit 1
}
stop_sub() {
  if [[ -n "$subpid" ]]; then kill "$subpid" 2>/dev/null || true; wait "$subpid" 2>/dev/null || true; subpid=''; fi
}
publish() {
  local label="$1" topic="$2" body="$3"
  timeout 6 mosquitto_pub -o "$TMP/$label.cfg" -i "pub-$label-$unique" -q 1 -t "$topic" -m "$body"
}
wait_message() {
  local file="$1" text="$2" i
  for i in {1..80}; do
    rg -F -q "$text" "$file" && return 0
    sleep 0.1
  done
  return 1
}
[[ "$(ss -lnt | rg ':8883\b' | rg '127\.0\.0\.1' | wc -l)" -ge 1 ]] || { echo 'Broker TLS loopback nao esta ativo' >&2; exit 1; }

if [[ "$MODE" == 'revoked' ]]; then
  echo '[1/2] Dispositivo nao revogado continua autenticando e publicando...'
  publish second "lab/sensors/$SECOND/telemetry" "$unique-active" || { echo 'FALHA: dispositivo ativo' >&2; exit 1; }
  echo '[2/2] Credencial do dispositivo revogado...'
  if [[ -e "$TMP/first.cfg" ]]; then
    if timeout 6 mosquitto_pub -d -o "$TMP/first.cfg" \
       -i "pub-first-$unique" -q 1 -t "lab/sensors/$FIRST/telemetry" \
       -m "$unique-revoked" > "$TMP/revoked.out" 2>&1; then
      echo 'FALHA: credencial revogada aceita para publicacao!' >&2; exit 1
    fi
    # Erro de rede/TLS nao e prova de revogacao: exigir rejeicao explicita.
    if ! rg -i -q 'CONNACK.*\(5\)|refused.*not authori[sz]ed|not authori[sz]ed.*refused' "$TMP/revoked.out"; then
      echo 'INCONCLUSIVO: cliente falhou, mas nao demonstrou rejeicao de autenticacao.' >&2
      exit 2
    fi
    echo 'APROVADO: login revogado rejeitado, conta restante ativa.'
  else
    echo 'INCONCLUSIVO para login: forneca RUST_SERVER_REVOKED_TOKEN_FILE (arquivo privado com senha ANTIGA) para testar a rejeicao; conta ativa validada.'
    exit 2
  fi
  exit 0
fi

echo '[1/7] Primeiro dispositivo publica apenas no proprio namespace...'
start_sub bridge "lab/sensors/$FIRST/#" "$TMP/bridge-one.out"
publish first "lab/sensors/$FIRST/telemetry" "$unique-own-write"
wait_message "$TMP/bridge-one.out" "$unique-own-write" || { cat "$TMP/bridge-one.out"; echo 'FALHA: escrita autorizada'; exit 1; }
stop_sub

echo '[2/7] Dispositivo nao pode publicar no namespace de outro...'
start_sub bridge "lab/sensors/$SECOND/#" "$TMP/bridge-two.out"
publish first "lab/sensors/$SECOND/telemetry" "$unique-other-write" > "$TMP/forbidden.pub" 2>&1 || true
sleep 2
if rg -F -q "$unique-other-write" "$TMP/bridge-two.out"; then cat "$TMP/bridge-two.out"; echo 'FALHA: escrita cruzada foi entregue!' >&2; exit 1; fi
stop_sub

echo '[3/7] Leitura autorizada das respostas do proprio dispositivo...'
start_sub first "bus/sensors/$FIRST/#" "$TMP/first-own.out"
publish bridge "bus/sensors/$FIRST/status" "$unique-own-read"
wait_message "$TMP/first-own.out" "$unique-own-read" || { cat "$TMP/first-own.out"; echo 'FALHA: leitura autorizada'; exit 1; }
stop_sub

echo '[4/7] Leitura proibida do namespace de outro dispositivo...'
start_sub first "bus/sensors/$SECOND/#" "$TMP/first-other.out"
publish bridge "bus/sensors/$SECOND/status" "$unique-other-read"
sleep 2
if rg -F -q "$unique-other-read" "$TMP/first-other.out"; then cat "$TMP/first-other.out"; echo 'FALHA: leitura cruzada foi entregue!' >&2; exit 1; fi
stop_sub

echo '[5/7] Dispositivos diferentes autenticam com senhas diferentes...'
publish second "lab/sensors/$SECOND/telemetry" "$unique-second-active"
echo '[6/7] Conta compartilhada lab nao pode publicar no namespace dos sensores...'
start_sub bridge "lab/sensors/$FIRST/#" "$TMP/legacy-write.out"
publish lab "lab/sensors/$FIRST/telemetry" "$unique-legacy-write" > "$TMP/legacy-write-pub.out" 2>&1 || true
sleep 2
if rg -F -q "$unique-legacy-write" "$TMP/legacy-write.out"; then
  cat "$TMP/legacy-write.out"; echo 'FALHA: lab conseguiu publicar em sensores!' >&2; exit 1
fi
stop_sub

echo '[7/7] Conta compartilhada lab nao pode ler respostas dos sensores...'
start_sub lab "bus/sensors/$FIRST/#" "$TMP/legacy-read.out"
publish bridge "bus/sensors/$FIRST/status" "$unique-legacy-read"
sleep 2
if rg -F -q "$unique-legacy-read" "$TMP/legacy-read.out"; then
  cat "$TMP/legacy-read.out"; echo 'FALHA: lab conseguiu ler dados de sensores!' >&2; exit 1
fi
stop_sub

echo 'APROVADO: dispositivos isolados, conta lab sem acesso a sensores, autorizacoes verificadas no plano de dados.'

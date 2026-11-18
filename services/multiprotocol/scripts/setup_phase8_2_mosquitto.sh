#!/usr/bin/env bash
# Broker MQTT com autenticação de conexão E autorização por tópico (Fase 8.2).
set -euo pipefail
umask 077
cd "$(dirname "$0")/.."
for bin in openssl mosquitto mosquitto_passwd mktemp install; do
  command -v "$bin" >/dev/null || { echo "Dependência ausente: $bin (Arch: sudo pacman -S mosquitto)" >&2; exit 1; }
done
[[ -f certs/ca.crt && -f certs/localhost.crt && -f certs/localhost.key ]] || {
  echo 'Certificados ausentes: execute bash scripts/setup_phase8.sh' >&2; exit 1;
}
openssl verify -CAfile certs/ca.crt -purpose sslserver certs/localhost.crt

SECRET_DIR="$HOME/.config/rust-server"
for name in mqtt-bridge.token mqtt-lab.token; do
  [[ -s "$SECRET_DIR/$name" ]] || { echo "Segredo ausente: $SECRET_DIR/$name" >&2; exit 1; }
done
# Evitar quebra de diretivas do mosquitto.conf (caminhos com espaço/control são rejeitados).
for value in "$PWD" "$HOME"; do
  if [[ "$value" =~ [[:space:]] ]]; then
    echo 'Caminho com espaços/quebras de linha não suportado neste instalador' >&2; exit 1
  fi
done
MQTT_DIR="$SECRET_DIR/mosquitto"
if [[ -f "$MQTT_DIR/devices.json" ]]; then
  echo 'ERRO: Fase 8.3 ativa; nao execute setup_phase8_2_mosquitto.sh, pois apagaria contas e ACLs de dispositivos.' >&2
  echo 'Use python3 scripts/gerenciar_dispositivos_fase8_3.py list/create/rotate/revoke.' >&2
  exit 1
fi
mkdir -p "$MQTT_DIR"
chmod 700 "$MQTT_DIR"
# Senhas planas existem brevemente somente em tmpfs privada, NÃO em argumentos do processo.
[[ -d /dev/shm && -w /dev/shm ]] || { echo 'Requer /dev/shm (tmpfs) para conversão de senhas sem disco' >&2; exit 1; }
TEMP_DIR="$(mktemp -d /dev/shm/rust-server-mqtt.XXXXXXXX)"
trap 'rm -rf "$TEMP_DIR"' EXIT
bridge_pass="$(tr -d '\r\n' < "$SECRET_DIR/mqtt-bridge.token")"
lab_pass="$(tr -d '\r\n' < "$SECRET_DIR/mqtt-lab.token")"
[[ ${#bridge_pass} -ge 32 && ${#lab_pass} -ge 32 && "$bridge_pass" != "$lab_pass" ]] || {
  echo 'Credenciais devem ser distintas e ter ao menos 32 caracteres.' >&2; exit 1;
}
printf 'bridge:%s\nlab:%s\n' "$bridge_pass" "$lab_pass" > "$TEMP_DIR/passwords"
unset bridge_pass lab_pass
# -U substitui senhas planas por hashes; NUNCA executar -U novamente no arquivo já hasheado.
mosquitto_passwd -U "$TEMP_DIR/passwords"
# Formato final esperado: nome:$hash (nunca texto simples).
if ! grep -q '^bridge:\$' "$TEMP_DIR/passwords" || ! grep -q '^lab:\$' "$TEMP_DIR/passwords"; then
  echo 'Conversão de senhas em hashes não confirmou o formato esperado.' >&2; exit 1
fi
cat > "$TEMP_DIR/acl" <<'ACL'
# Política de menor privilégio: nenhum tópico fora das regras é autorizado.
user bridge
topic read lab/alerts
topic read lab/sensors/#
topic write bus/alerts
topic write bus/sensors/#

user lab
topic write lab/alerts
topic write lab/sensors/#
topic read bus/alerts
topic read bus/sensors/#
ACL
cat > "$TEMP_DIR/mosquitto.conf" <<EOF
# Gerado pela Fase 8.2. Executar COMO USUÁRIO NÃO PRIVILEGIADO, sem sudo.
listener 8883 127.0.0.1
allow_anonymous false
password_file $MQTT_DIR/passwords
acl_file $MQTT_DIR/acl
certfile $PWD/certs/localhost.crt
keyfile $PWD/certs/localhost.key
tls_version tlsv1.2
persistence false
max_connections 64
max_packet_size 8192
message_size_limit 2048
max_queued_messages 64
max_queued_bytes 65536
log_dest stderr
log_type error
log_type warning
log_type notice
EOF
# Backup dos arquivos existentes; nunca sobrescrever senhas sem snapshot anterior.
BACKUP_DIR="$MQTT_DIR/backup-$(date +%Y%m%d-%H%M%S)-$$"
mkdir -m 700 "$BACKUP_DIR"
for file in passwords acl mosquitto.conf; do
  if [[ -e "$MQTT_DIR/$file" ]]; then cp -p "$MQTT_DIR/$file" "$BACKUP_DIR/$file"; fi
done
install -m 600 "$TEMP_DIR/passwords" "$MQTT_DIR/passwords"
install -m 600 "$TEMP_DIR/acl" "$MQTT_DIR/acl"
install -m 600 "$TEMP_DIR/mosquitto.conf" "$MQTT_DIR/mosquitto.conf"
chmod 600 "$MQTT_DIR"/{passwords,acl,mosquitto.conf}
echo "[8.2] Configuração preparada: $MQTT_DIR/mosquitto.conf"
echo '[8.2] Senhas armazenadas somente como hashes no arquivo do broker.'
echo '[8.2] Certificados e tokens anteriores preservados.'
echo '[8.2] Use scripts/run_phase8_2_mosquitto.sh num terminal separado, SEM sudo.'
echo '[AVISO] acl_file/password_file são legados no Mosquitto >=2.1 e serão removidos no 3.0; migre para plugins antes desse upgrade.'

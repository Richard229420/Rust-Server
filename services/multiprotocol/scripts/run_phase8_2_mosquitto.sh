#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
CONF="$HOME/.config/rust-server/mosquitto/mosquitto.conf"
[[ -s "$CONF" ]] || { echo 'Execute scripts/setup_phase8_2_mosquitto.sh primeiro.' >&2; exit 1; }
[[ "$(id -u)" -ne 0 ]] || { echo 'Não execute o broker com sudo/root.' >&2; exit 1; }
if ss -lnt | grep -Eq '127[.]0[.]0[.]1:8883[[:space:]]'; then
  echo 'Porta 8883 já está ocupada; interrompa o multiprotocolo antigo com rumqttd.' >&2
  exit 1
fi
exec mosquitto -c "$CONF" -v

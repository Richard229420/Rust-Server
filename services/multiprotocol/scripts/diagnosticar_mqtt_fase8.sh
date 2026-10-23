#!/usr/bin/env bash
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2
: "${RUST_SERVER_MQTT_LAB_PASSWORD:?Rode source scripts/env_phase8.sh}"
for cmd in openssl mosquitto_pub timeout; do
  command -v "$cmd" >/dev/null || { echo "Ferramenta ausente: $cmd" >&2; exit 2; }
done
printf '[1/3] Certificado do broker MQTT (TLS somente)...\n'
if ! timeout 8 openssl s_client -connect 127.0.0.1:8883 -servername localhost -CAfile certs/ca.crt -verify_return_error -brief </dev/null 2>&1 | sed -n '1,20p'; then
  echo 'Verifique se o multiprotocolo foi iniciado no Terminal B' >&2
fi
printf '\n[2/3] CONNECT MQTT v3.1.1 pelo mosquitto (TLS 1.3/negociado)...\n'
if timeout 8 mosquitto_pub -d -V mqttv311 -i "fase8-diagnostico-$$" \
  -h localhost -p 8883 --cafile certs/ca.crt \
  -u lab -P "$RUST_SERVER_MQTT_LAB_PASSWORD" \
  -t lab/alerts -m fase8-diagnostico-um; then
  echo 'RESULTADO: cliente Mosquitto publicou (CONNECT aceito).'
else
  echo 'RESULTADO: falha no MQTT (observe a saida [MQTT-AUTH] no Terminal B).'
fi
printf '\n[3/3] CONNECT MQTT v3.1.1 forcando TLS 1.2 (teste de compatibilidade)...\n'
if timeout 8 mosquitto_pub -d -V mqttv311 --tls-version tlsv1.2 \
  -i "fase8-diagnostico-tls12-$$" -h localhost -p 8883 \
  --cafile certs/ca.crt -u lab -P "$RUST_SERVER_MQTT_LAB_PASSWORD" \
  -t lab/alerts -m fase8-diagnostico-dois; then
  echo 'RESULTADO: cliente Mosquitto com TLS 1.2 publicou.'
else
  echo 'RESULTADO: falha tambem com TLS 1.2.'
fi
printf '\nConcluido. Este script diagnostica apenas; NAO certifica ACL MQTT nem seguranca em producao.\n'

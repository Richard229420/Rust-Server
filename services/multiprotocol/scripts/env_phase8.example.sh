# Carregue somente com: source scripts/env_phase8.sh (zsh/bash)
# Nao imprima os valores das variaveis. Nao adicione os tokens ao git.
SECRETS_DIR="$HOME/.config/rust-server"
export RUST_SERVER_BUS_TOKEN="$(tr -d '\r\n' < "$SECRETS_DIR/bus.token")"
export RUST_SERVER_BUS_READ_TOKEN="$(tr -d '\r\n' < "$SECRETS_DIR/bus-read.token")"
export RUST_SERVER_BUS_WRITE_TOKEN="$(tr -d '\r\n' < "$SECRETS_DIR/bus-write.token")"
export RUST_SERVER_MQTT_BRIDGE_PASSWORD="$(tr -d '\r\n' < "$SECRETS_DIR/mqtt-bridge.token")"
export RUST_SERVER_MQTT_LAB_PASSWORD="$(tr -d '\r\n' < "$SECRETS_DIR/mqtt-lab.token")"
unset SECRETS_DIR

# Estado seguro padrao: transporte UDP legado permanece desabilitado.
unset RUST_SERVER_ENABLE_LEGACY_UDP

# Clientes MQTT/TCP e bridge validam o certificado do servidor usando a CA local.
export RUST_SERVER_TLS_CA="certs/ca.crt"

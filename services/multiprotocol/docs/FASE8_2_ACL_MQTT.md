# Fase 8.2 — ACL MQTT de verdade (Mosquitto + bridge Rust)

**Base:** servidor HTTP 6.4, multiprotocolo Rust v0.2.0 + hardening Fase 8.1.
**Escopo:** substituir APENAS o broker MQTT `rumqttd` incorporado por **Mosquitto externo local**; manter gateway HTTPS, barramento TCP/TLS, tokens e bridge MQTT em Rust.
**Status:** patch disponibilizado para compilação e testes NO Arch Linux do projeto. Não significa auditoria de segurança de produção.

## Por que muda?

Os testes anteriores demonstraram que um cliente autenticado como `lab` podia assinar `internal/fase8-acl-probe`, pois `rumqttd` validava somente `CONNECT`. A Fase 8.2 delega a checagem **PUBLISH/SUBSCRIBE por usuário e tópico** ao broker Mosquitto; somente o filtro da bridge não seria suficiente.

Em Mosquitto 2.1, `acl_file` e `password_file` estão **obsoletos**, mas ainda são suportados. Devem ser substituídos pelos plugins oficiais correspondentes **antes de atualizar para Mosquitto 3.0**. O objetivo deste patch é funcionar com a linha Mosquitto 2.x no laboratório Arch.

## Política do broker

| Conta MQTT | Pode PUBLICAR | Pode RECEBER |
|---|---|---|
| `lab` | `lab/alerts`, `lab/sensors/#` | `bus/alerts`, `bus/sensors/#` |
| `bridge` | `bus/alerts`, `bus/sensors/#` | `lab/alerts`, `lab/sensors/#` |

O acesso a `internal/#`, `admin/#` e demais tópicos fica sem permissão explícita. Mesmo se o broker enviar `SUBACK` de sucesso para um filtro, a auditoria só aprova se as mensagens efetivamente bloqueadas **não forem entregues**.

## Pré-requisitos

- Arch Linux; Rust/Cargo já instalados; `mosquitto`, `mosquitto_pub`, `mosquitto_sub`, `mosquitto_passwd` (pacote `mosquitto`). Se faltar: `sudo pacman -Syu mosquitto`.
- Certificados Fase 8 corrigidos em `certs/ca.crt`, `certs/localhost.crt`, `certs/localhost.key` (não regere, salvo expiração/comprometimento).
- Credenciais atuais `~/.config/rust-server/mqtt-bridge.token` e `mqtt-lab.token`; o script **não as substitui**.
- `/dev/shm` montado como tmpfs para conversão momentânea do arquivo de senhas em hashes.
- Serviços MQTT/TCP expostos apenas a `127.0.0.1`, sem redirecionamento de portas.

## Atualização sem destruir os arquivos que funcionam

Interrompa **somente** o multiprotocolo antigo antes de usar a porta 8883, mantendo o HTTP em execução. Extraia `fase8-2-acl-mqtt.zip` em `~/Downloads`.

```bash
cd ~/Downloads && unzip fase8-2-acl-mqtt.zip
cd ~/server/services/multiprotocol
BACKUP="$HOME/Downloads/backup-fase8-2-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP"
cp -a Cargo.toml src/main.rs src/config.rs src/mqtt.rs src/bridge.rs scripts "$BACKUP/"
PATCH="$HOME/Downloads/fase8-2-acl-mqtt"
cp -av "$PATCH/Cargo.toml" ./
cp -av "$PATCH/src/"*.rs ./src/
cp -av "$PATCH/scripts/"*.sh ./scripts/
cp -av "$PATCH/docs/FASE8_2_ACL_MQTT.md" ./docs/
```

**Atenção:** o patch inclui somente os quatro módulos Rust alterados; o comando copia `src/*.rs` do patch, não os demais módulos do servidor. Não substitua `src/messaging.rs`, `src/https.rs`, `examples/bus_client.rs` nem certificados.

Execute (como usuário comum):

```bash
bash scripts/setup_phase8_2_mosquitto.sh
cargo fmt
cargo fmt --check
cargo check --all-targets
cargo test --all-targets
```

### Executar em três terminais

Terminal A — servidor HTTP (já conhecido):
```bash
cd ~/server && cargo run
```

Terminal B — broker MQTT EXTERNO (não use `sudo`):
```bash
cd ~/server/services/multiprotocol
bash scripts/run_phase8_2_mosquitto.sh
```

Terminal C — Rust HTTPS + TCP/TLS + bridge (aguarde broker iniciar antes):
```bash
cd ~/server/services/multiprotocol
source scripts/env_phase8.sh
cargo run
```

Terminal D — auditoria:
```bash
cd ~/server/services/multiprotocol
source scripts/env_phase8.sh
bash scripts/test_phase8_2_acl.sh
bash scripts/test_phase8_1_tcp_acl.sh
bash scripts/test_phase8_security.sh
```

Resultado esperado da auditoria: `APROVADO: positivos e negativos de leitura/escrita MQTT (entrega real verificada).` Se qualquer comando falhar, interrompa a implantação: verifique logs do broker B, bridge C e saída do script D; não abra rede.

A porta 8883 agora pertence ao **processo `mosquitto`**, e não a `rust-server-mul`:
```bash
ss -lntup | rg ':(8080|8443|8883|7001|1883|7002)\b'
```

O arquivo `configs/rumqttd.toml` foi mantido apenas como registro histórico, **não é mais carregado**. `RUST_SERVER_MQTT_CONFIG` também deixa de ser usado.

## Segurança e limitações

- O serviço não usa mTLS MQTT, não possui usuário/senha individual para cada dispositivo (a conta `lab` é compartilhada) e ainda não faz revogação por dispositivo.
- Mensagens ainda usam MQTT QoS 0 na bridge, sem persistência garantida nem reenvio de eventos. Limites de memória e conexões reduzem risco de abuso, mas não garantem imunidade a DoS.
- O gateway HTTPS original e a API continuam com suas políticas existentes; esta atualização **não** os audita.
- Mosquitto será um **processo separado**, com seu ciclo de atualização, monitoramento e correções de segurança. Mantenha o pacote atualizado via pacman e execute sem root.
- As senhas são mantidas nos arquivos `.token` (0600) já existentes para compatibilidade com a bridge. O arquivo `passwords` do broker armazena hashes (argon2id em versões recentes). Senhas passadas aos clientes `mosquitto_pub/sub` por `-P` ficam temporariamente visíveis em argumentos de processo. Evite esse método fora do laboratório.
- TLS usa CA local; mantenha `certs/ca.key` e `certs/localhost.key` fora de repositórios e backups sem proteção.
- `acl_file/password_file` devem migrar para plugins da linha Mosquitto 2.1+ antes da versão 3.0; não aplique atualização maior às cegas.
- **Não expor a porta 8883/7001 à LAN** apenas porque os testes passaram; primeiro faça identidades individuais, auditoria, fuzzing, observabilidade e implantação isolada com systemd/VPN/mTLS, conforme necessidade.

## Plano de retorno

Interrompa primeiro Rust (C) e Mosquitto (B). Restaure os quatro módulos e Cargo.toml do backup. Execute `source scripts/env_phase8.sh && cargo run` no multiprotocolo para reativar o broker embutido **somente no loopback**, até corrigir eventuais falhas do novo broker. Não inicie ambos os brokers na porta 8883.

# Fase 8.1 — Endurecimento do barramento TCP/TLS e auditoria MQTT

**Ponto de partida:** Rust-Server Multiprotocolo v0.2.0 (Fase 8) atualizado com os patches de diagnostico MQTT e `close_notify`. **Nao atualiza** o servidor HTTP original em `~/server/src`.

## Ajustes no codigo Rust

O `src/messaging.rs` agora armazena assinantes por `(topico, connection_id)` e impede repeticoes do comando `SUB` de produzirem inscricoes duplicadas. Ao encerrar a conexao, suas inscricoes sao removidas via `Drop` (`SubscriptionGuard`). Foram adicionados limites de **16 topicos distintos por sessao**, **64 assinantes por topico** e mantidos os limites anteriores (128 topicos no total, 64 clientes TCP simultaneos, 30 comandos por segundo). Rejeicoes por limite e sobrecarga de conexoes deixam registros sem credenciais.

A publicacao MQTT e o gateway HTTPS nao foram modificados. MQTT permanece com autenticacao de conexao (`CONNECT`) e TLS, mas **NAO** possui autorizacao de leitura/escrita por topico no broker `rumqttd 0.20.0`. O filtro da bridge `lab/*` nao protege topicos no proprio broker.

## Instalar sem perder a Fase 8

Interrompa apenas o multiprotocolo (Terminal B), mantendo o HTTP no Terminal A. Extraia `fase8-1-hardening.zip` em `~/Downloads`:

```bash
cd ~/Downloads && unzip fase8-1-hardening.zip
cd ~/server/services/multiprotocol
BACKUP="$HOME/Downloads/backup-fase8-1-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP"
cp -a src/messaging.rs scripts "$BACKUP/"
PATCH="$HOME/Downloads/fase8-1-hardening"
cp -av "$PATCH/src/messaging.rs" src/messaging.rs
cp -av "$PATCH/scripts/"*.sh scripts/
cp -av "$PATCH/docs/FASE8_1_HARDENING.md" docs/
cargo fmt
cargo fmt --check
cargo check --all-targets
cargo test --all-targets
source scripts/env_phase8.sh
cargo run
```

Se houve edicoes manuais recentes em `src/messaging.rs`, compare-as antes de copiar. **Nao sobrescreva** `src/mqtt.rs`, `src/bridge.rs`, certificados ou credenciais.

## Testar com HTTP (A) e multiprotocolo (B) em execucao

Em outro terminal:

```bash
cd ~/server/services/multiprotocol
source scripts/env_phase8.sh
bash scripts/test_phase8_1_tcp_acl.sh
bash scripts/test_phase8_1_mqtt_auth.sh
bash scripts/auditar_acl_mqtt.sh
```

O ultimo comando **deve retornar codigo 2 no broker atual**, indicando que um cliente `lab` consegue assinar `internal/fase8-acl-probe`. Isso significa que a ACL MQTT por topico AINDA NAO foi implementada e que a exposicao a clientes nao confiaveis permanece proibida.

`bash scripts/test_phase8_security.sh` continua disponivel para regressao bidirecional da bridge, mas usa verificacoes antigas e nao substitui os testes novos.

## Politica segura para este estagio

- Mantenha `127.0.0.1` em MQTT/TCP. Nao redirecione portas 8883/7001 para toda a rede.
- UDP legado desabilitado.
- Nunca grave segredos, chaves privadas nem o arquivo `env_phase8.sh` com variaveis expandidas em Git.
- As credenciais de `lab` nao devem ser entregues a usuarios/dispositivos nao confiaveis ate que exista ACL real no broker.
- O proximo grande passo e adotar ou desenvolver uma implementacao MQTT com autorizacao por `PUBLISH`/`SUBSCRIBE` e testes de negacao de topico no plano de dados. Apenas um `auth_handler` no CONNECT nao garante essa politica.

## Validacao

Sintaxe Bash e integridade do ZIP foram verificadas no ambiente de autoria. `cargo`/`rustc` nao estavam disponiveis para compilacao aqui: os testes Rust e os testes funcionais devem ser executados no Arch Linux.

# Fase 7 — Bridge MQTT ↔ TCP/UDP (bus/1)

## O que mudou

A versao anterior ja tinha MQTT, TCP e UDP, mas o MQTT nao participava do barramento.
A Fase 7 adiciona `src/bridge.rs` e conecta o cliente Rust `rumqttc` ao broker
incorporado `rumqttd`, sem substituir o HTTP/HTTPS ou a API REST original.

### Mapeamento de topicos (direcional)

| Origem | Topico usado na origem | Destino | Topico usado no destino |
| --- | --- | --- | --- |
| MQTT | `lab/alerts` | Assinantes TCP | `alerts` |
| MQTT | `lab/sensors/temp` | Assinantes TCP | `sensors/temp` |
| TCP ou UDP | `alerts` | Assinantes MQTT | `bus/alerts` |
| TCP ou UDP | `sensors/temp` | Assinantes MQTT | `bus/sensors/temp` |

**Por que os topicos sao diferentes?** Se a bridge inscrevesse e publicasse no
mesmo topico MQTT v3.1.1 (`lab/alerts`), o cliente da propria bridge receberia
sua publicacao. A separacao `lab/*` (entrada) de `bus/*` (saida), combinada com
identificacao de origem, evita recirculacao de eventos.

Somente topicos de `bus/1` validos (ate 64 bytes, caracteres ASCII
alfanumericos e `/`, `-`, `_`, `.`) podem atravessar a bridge. Mensagens sao
texto UTF-8 valido, ate 2048 bytes, sem controles/quebras de linha. Mensagens
MQTT retidas sao ignoradas.

## Atualizacao do projeto existente

1. Pare apenas o **Terminal B** (`Ctrl+C`). Mantenha o Terminal A com
   `~/server` em execucao.
2. Extraia o ZIP **completo da Fase 7** em `~/Downloads` e efetue backup do
   `services/multiprotocol` antes de substituir os arquivos de codigo.
3. **Nao copie** `certs/`, `target/`, nenhum arquivo contendo tokens ou o
   banco de dados a partir de pacotes. O ZIP nao contem segredos.
4. Execute `cargo fmt`, `cargo fmt --check`, `cargo check`, `cargo test`, `cargo run`
   dentro de `~/server/services/multiprotocol`.
5. No terminal do broker, aguarde a linha `[BRIDGE] MQTT conectado em ...`.
   Se estiver desconectado, a bridge voltara a tentar, mas mensagens podem
   ser perdidas durante a indisponibilidade.

**Alternativa:** use o ZIP `fase7-bridge-atualizacao.zip`, que contem somente
`Cargo.toml`, `README.md`, `src/main.rs`, `src/mqtt.rs`, `src/messaging.rs`,
`src/bridge.rs`, `configs/rumqttd.toml` (com `dynamic_filters = true`),
esta documentacao e script de teste. O restante da estrutura
local permanece intacto.

## Testes passo a passo (4 terminais)

Terminais A e B ja em execucao:

```bash
# Terminal A: Rust HTTP original (~/server)
cargo run

# Terminal B: ~/server/services/multiprotocol
export RUST_SERVER_BUS_TOKEN="$(cat ~/.config/rust-server/bus.token)"
cargo fmt
cargo fmt --check
cargo check
cargo test
cargo run
```

Terminal C: assinante TCP (use o mesmo token criado anteriormente).

```bash
cd ~/server/services/multiprotocol
export RUST_SERVER_BUS_TOKEN="$(cat ~/.config/rust-server/bus.token)"
cargo run --example bus_client -- tcp-sub alerts
# esperado: HELLO ..., OK AUTH, OK SUB
```

Terminal D: publicacao MQTT de entrada.

```bash
mosquitto_pub -h 127.0.0.1 -p 1883 -t 'lab/alerts' -m 'evento vindo do MQTT'
# esperado no Terminal C: MSG alerts evento vindo do MQTT
```

Agora, no Terminal D, assine a **saida** da bridge:

```bash
mosquitto_sub -h 127.0.0.1 -p 1883 -t 'bus/alerts'
```

Em outro terminal (E), publique do TCP:

```bash
cd ~/server/services/multiprotocol
export RUST_SERVER_BUS_TOKEN="$(cat ~/.config/rust-server/bus.token)"
cargo run --example bus_client -- tcp-pub alerts 'evento vindo do TCP'
# esperado no Terminal D: evento vindo do TCP
```

Repita a publicacao por UDP:

```bash
cargo run --example bus_client -- udp-pub alerts 'evento vindo do UDP'
# esperado no Terminal D: evento vindo do UDP
```

Se preferir, com A e B ativos, execute o teste automatizado:

```bash
bash scripts/test_phase7_bridge.sh
```

## Limites, falhas e seguranca

- **Somente loopback.** MQTT 1883 nao possui senha nem TLS nesta fase;
  TCP/UDP usam token em texto puro. Nao exponha na rede LAN ou Internet.
- **QoS 0, best-effort.** Sem persistencia, confirmacao de processamento remoto,
  retry por mensagem, nem entrega exatamente uma vez. Uma bridge conectada
  nao substitui MQTT QoS 1/2.
- O bus usa uma fila limitada a **256 mensagens** para bridge; `try_send`
  evita bloquear produtores. Ao lotar, descarta a mensagem da bridge e
  retorna `OK PUB N BRIDGE_DROPPED` (a entrega local pode continuar).
- O cliente `rumqttc` tem outra fila interna limitada. O stderr registra
  seus erros, mas `OK PUB N` nao garante confirmacao MQTT.
- A `subscription lab/#` captura apenas eventos direcionados a `lab/*`.
  Tentar copiar `bus/alerts` para `lab/alerts` por outro software pode
  gerar novas publicacoes; a bridge so previne loops criados por ela.
- A base SQL, credenciais RBAC e rotas HTTPS originais permanecem intocadas.
- Proximas fases: MQTTS + credenciais/ACL, indicadores de entrega e
  filas persistentes, testes de carga e systemd.

## Configuracao importante: MQTT wildcard

A bridge assina `lab/#` para receber diferentes topicos. A configuracao
`configs/rumqttd.toml` desta fase passa a usar `dynamic_filters = true`
para permitir a criacao dinamica dos filtros/subscricoes. Continue mantendo
`listen = "127.0.0.1:1883"`. Se voce ja personalizou este arquivo, revise
a diferenca antes de substitui-lo.

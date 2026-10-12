# Rust HTTP Server — Incremento Fase 3

**Aplicacao incremental**, sem refatorar/mover a estrutura Rust atual do projeto. Adiciona testes de integracao HTTP e metricas de observabilidade ao pool de 16 workers e fila 128.

## Arquivos deste pacote

```text
src/server.rs                   # Substituir o server.rs atual (backup antes)
src/metrics.rs                  # Adicionar novo modulo de metricas
tests/integration_http.py       # Testes HTTP/TCP automatizados
tests/load_test_16000.py       # Mesmo gerador de benchmark ja utilizado
scripts/test_phase3.sh          # Checagem e teste automatizado
docs/FASE3.md                   # Instalacao, operacao e riscos
docs/PROXIMOS_PROTOCOLOS.md     # HTTPS, AMQP, NATS, HTTP/2, TCP/UDP etc.
observability/prometheus.yml    # Exemplo de coleta Prometheus local
observability/Caddyfile.example # Exemplo de TLS local via Caddy e bloqueio de /metrics
```

## Inicio rapido

Salve backup do projeto e copie, da raiz do projeto, apenas `src/server.rs`, `src/metrics.rs` e `tests/integration_http.py` para os caminhos homonimos. Os demais arquivos sao opcionais.

```bash
cd ~/server
cp src/server.rs src/server.rs.bak
# Exemplo com pacote extraido em ~/Downloads/rust_http_phase3:
cp ~/Downloads/rust_http_phase3/src/server.rs src/server.rs
cp ~/Downloads/rust_http_phase3/src/metrics.rs src/metrics.rs
mkdir -p tests
cp ~/Downloads/rust_http_phase3/tests/integration_http.py tests/
cargo fmt && cargo check && cargo test && cargo build --release
python3 tests/integration_http.py
```

**Antes dos testes de integracao, encerre um servidor antigo na porta 8080.** O teste inicia sua propria instancia e a encerra em seguida. Logs de teste em `integration_server.log`.

Explore os endpoints com `curl -i http://127.0.0.1:8080/health` e `curl -s http://127.0.0.1:8080/metrics`, mantendo o servidor em execucao.

Leia `docs/FASE3.md` para todos os detalhes, metricas e limitacoes. Esta entrega nao altera `main.rs`, `router.rs`, `request.rs` nem `response.rs`.

**Validacao:** Codigo revisto e testes Python validados sintaticamente, mas compilacao/testes Rust **nao executados aqui por ausencia de Cargo/rustc e dos modulos originais completos**. A confirmacao ocorre no seu ambiente Arch Linux.

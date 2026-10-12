# Fase 3 — Testes de integração e observabilidade

Este pacote é **incremental**: mantém a organização de `~/server/src` e os módulos já existentes. Atualiza apenas `src/server.rs`, adiciona `src/metrics.rs` e acrescenta testes/scripts.

## Recursos entregues

- **16 workers fixos**, **fila limitada de 128**, 5 s de timeout de leitura e 15 s de prazo total desde a entrada na fila.
- `GET /health`: responde `200`, `Content-Type: text/plain`, body `ok\n`.
- `GET /metrics`: métricas no formato de exposição do Prometheus, **apenas para conexões originadas em loopback**.
- Contadores de conexões aceitas, workers ocupados/pico, tamanho/pico da fila, rejeições por sobrecarga, timeouts por inatividade e por prazo, respostas por código e histograma de latência.
- Testes reais via sockets TCP cobrindo GET, 404, 405, 400, 413, 408, fragmentação de headers e body, `/health`, `/metrics` e, opcionalmente, saturação 503.
- Dependências adicionais no Rust: **nenhuma**. Python 3.10+ stdlib para os testes.

## Aplicação com backup

Da pasta raiz do repositório, após baixar/extrair o pacote:

```bash
cd ~/server
mkdir -p ~/backups
cp -a src/server.rs ~/backups/server_antes_fase3.rs
cp ~/Downloads/rust_http_phase3/src/server.rs src/server.rs
cp ~/Downloads/rust_http_phase3/src/metrics.rs src/metrics.rs
mkdir -p tests
cp ~/Downloads/rust_http_phase3/tests/integration_http.py tests/integration_http.py
```

O comando acima supõe que o pacote foi extraído como `~/Downloads/rust_http_phase3`. Se o local for outro, adapte o caminho. **Não é necessário mudar `main.rs`**, pois a declaração local de `metrics.rs` está dentro de `server.rs`.

```bash
cargo fmt
cargo check
cargo test
cargo build --release
```

O `cargo test` anterior tinha 9 testes; foi acrescentado **1 teste unitário de métricas** (esperado: 10 testes aprovados se nada mais mudou).

## Integração automatizada

Pare qualquer servidor que esteja ocupando a porta 8080 e execute:

```bash
python3 tests/integration_http.py
```

O script constrói o binário `release`, inicia a aplicação, verifica os endpoints HTTP por sockets reais, registra logs em `integration_server.log` e encerra o processo ao terminar. Use `--running` para um servidor já iniciado, `--quick` para pular os dois testes de 5 segundos, e `--stress` para incluir saturação do pool (16 workers + 128 na fila); o teste de saturação é **local e opcional**.

O resultado esperado é `OK` (os testes de timeout levarão cerca de 10 segundos). **O resultado definitivo depende da compilação e execução no seu projeto**.

## Verificação manual

Em um terminal, inicie:

```bash
cargo run --release
```

Em outro:

```bash
curl -i http://127.0.0.1:8080/health
curl -s http://127.0.0.1:8080/metrics
curl -s http://127.0.0.1:8080/metrics | grep '^rust_http_'
```

Em Zsh com `grep` configurado como alias de `rg`, use `rg '^rust_http_'` no lugar do último `grep`.

O exemplo `observability/prometheus.yml` faz scrape local a cada 5 segundos e pressupõe que o processo Prometheus tenha acesso a `127.0.0.1:8080` **no mesmo namespace de rede** (em contêineres isso costuma ser diferente).

## Definição das métricas

| Série | Tipo | Definição |
|---|---|---|
| `rust_http_connections_accepted_total` | counter | TCPs aceitos pelo processo, inclusive probes. |
| `rust_http_workers_active` | gauge | Workers ocupados neste instante. |
| `rust_http_workers_peak` | gauge | Maior quantidade de workers ocupados observada. |
| `rust_http_queue_depth` | gauge | Conexões registradas como pendentes de atendimento. |
| `rust_http_queue_peak` | gauge | Pico observado da fila, limitado à capacidade 128. |
| `rust_http_overload_rejected_total` | counter | Rejeições por fila cheia (tenta resposta 503). |
| `rust_http_read_timeouts_total` | counter | Excesso de inatividade por leitura. |
| `rust_http_deadline_timeouts_total` | counter | Prazo de recebimento de 15 s expirado. |
| `rust_http_responses_total{status="..."}` | counter | Respostas cujo envio por `write_all` concluiu. |
| `rust_http_response_duration_seconds` | histogram | Tempo desde aceitação TCP até a resposta, incluindo fila. |
| `rust_http_uptime_seconds` | gauge | Tempo desde início do processo. |

Obs.: snapshots de contadores atômicos não são uma fotografia transacional de todas as séries: podem variar ligeiramente sob concorrência. A consulta a `/metrics` é contabilizada **após** enviar a resposta e aparecerá no scrape seguinte. `queue_depth` pode mostrar incrementos transitórios durante uma tentativa de admissão concorrente.

## Notas de segurança / escopo

- HTTP permanece **sem criptografia**; mantenha a escuta em `127.0.0.1` até integrar TLS via proxy confiável ou biblioteca adequada.
- `/metrics` confere o IP TCP de origem como loopback; **um proxy local se apresenta como cliente local**, logo deverá bloquear `/metrics` explicitamente para clientes externos. Não considere essa verificação substituta para firewall/autenticação.
- `/health` é uma verificação simples de disponibilidade de processo, **não** de dependências ou de disponibilidade real do serviço sob carga.
- O servidor experimental **não oferece conformidade completa com HTTP/1.1** (p.ex. keep-alive, framing avançado, `Expect: 100-continue`, proxy headers, requisições HTTP pipelined). Não o exponha diretamente na internet nem o utilize com dados sensíveis.
- O limite de 15 s cobre fila e **recebimento HTTP**, não é um prazo rigoroso de execução dos handlers nem de envio de respostas.
- O protocolo HTTP/3 utiliza QUIC sobre UDP e não é fornecido por este projeto.
- Benchmarks medidos localmente não são previsão de desempenho em redes externas.
